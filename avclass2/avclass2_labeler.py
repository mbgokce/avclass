#!/usr/bin/env python
'''
AVClass2 labeler
'''

import os
import sys
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(1, os.path.join(script_dir, 'lib/'))
sys.path.insert(1, os.path.join(script_dir, '../shared/'))
import argparse
from avclass2_common import AvLabels
from operator import itemgetter
import evaluate_clustering as ec
import json
import traceback

# Default tagging file
default_tag_file = os.path.join(script_dir, "data/default.tagging")
# Default expansion file
default_exp_file = os.path.join(script_dir, "data/default.expansion")
# Default taxonomy file
default_tax_file = os.path.join(script_dir, "data/default.taxonomy")

def guess_hash(h):
    ''' Given a hash string, guess the hash type based on the string length '''
    hlen = len(h)
    if hlen == 32:
        return 'md5'
    elif hlen == 40:
        return 'sha1'
    elif hlen == 64:
        return 'sha256'
    else:
        return None

def format_tag_pairs(l, taxonomy=None):
    ''' Return ranked tags as string '''
    if not l:
        return ""
    if taxonomy is not None:
        p = taxonomy.get_path(l[0][0])
    else:
        p = l[0][0]
    out = "%s|%d" % (p, l[0][1])
    for (t,s) in l[1:]:
        if taxonomy is not None:
            p = taxonomy.get_path(t) 
        else:
            p = t
        out += ",%s|%d" % (p, s)
    return out

def list_str(l, sep=", ", prefix=""):
    ''' Return list as a string '''
    if not l:
        return ""
    out = prefix + l[0]
    for s in l[1:]:
        out = out + sep + s
    return out


def labeler(config_dict, sample_info, hash_type, av_labels, stats_dict):

    # If no sample info, log error and continue
    if sample_info is None:
        try:
            name = hash_type
            sys.stderr.write('\nNo scans for %s\n' % name)
        except KeyError:
            sys.stderr.write('\nCould not process: %s\n' % line)
        sys.stderr.flush()
        stats_dict['stats']['noscans'] += 1

    # Sample's name is selected hash type (md5 by default)
    name = getattr(sample_info, hash_type)

    # If the VT report has no AV labels, output and continue
    if not sample_info.labels:
        sys.stdout.write('%s\t-\t[]\n' % (name))
        # sys.stderr.write('\nNo AV labels for %s\n' % name)
        # sys.stderr.flush()

    # Compute VT_Count
    vt_count = len(sample_info.labels)

    # Get the distinct tokens from all the av labels in the report
    # And print them. 
    try:
        av_tmp = av_labels.get_sample_tags(sample_info)
        tags = av_labels.rank_tags(av_tmp)

        # AV VENDORS PER TOKEN
        if config_dict['avtags']:
            for t in av_tmp:
                tmap = stats_dict['avtags_dict'].get(t, {})
                for av in av_tmp[t]:
                    ctr = tmap.get(av, 0)
                    tmap[av] = ctr + 1
                stats_dict['avtags_dict'][t] = tmap

        if config_dict['aliasdetect']:
            prev_tokens = set()
            for entry in tags:
                curr_tok = entry[0]
                curr_count = stats_dict['token_count_map'].get(curr_tok, 0)
                stats_dict['token_count_map'][curr_tok] = curr_count + 1
                for prev_tok in prev_tokens:
                    if prev_tok < curr_tok:
                        pair = (prev_tok,curr_tok)
                    else:
                        pair = (curr_tok,prev_tok)
                    pair_count = stats_dict['pair_count_map'].get(pair, 0)
                    stats_dict['pair_count_map'][pair] = pair_count + 1
                prev_tokens.add(curr_tok)

        # Collect stats
        # FIX: should iterate once over tags, 
        # for both stats and aliasdetect
        if tags:
            stats_dict['stats']["tagged"] += 1
            if config_dict['stats']:
                if (vt_count > 3):
                    stats_dict['stats']["maltagged"] += 1
                    cat_map = {'FAM': False, 'CLASS': False,
                               'BEH': False, 'FILE': False, 'UNK':False}
                    for t in tags:
                        path, cat = av_labels.taxonomy.get_info(t[0])
                        cat_map[cat] = True
                    for c in cat_map:
                        if cat_map[c]:
                            stats_dict['stats'][c] += 1

        # Check if sample is PUP, if requested
        if config_dict['pup']:
            if av_labels.is_pup(tags, av_labels.taxonomy):
                is_pup_str = "\t1"
            else:
                is_pup_str = "\t0"
        else:
            is_pup_str =  ""

        # Select family for sample if needed,
        # i.e., for compatibility mode or for ground truth
        if config_dict['c'] or config_dict['gt']:
            fam = "SINGLETON:" + name
            # fam = ''
            for (t,s) in tags:
                cat = av_labels.taxonomy.get_category(t)
                if (cat == "UNK") or (cat == "FAM"):
                    fam = t
                    break

        # Get ground truth family, if available
        if config_dict['gt']:
            stats_dict['first_token_dict'][name] = fam
            gt_family = '\t' + gt_dict.get(name, "")
        else:
            gt_family = ""

        # Get VT tags as string
        if config_dict['vtt']:
            vtt = list_str(sample_info.vt_tags, prefix="\t")
        else:
            vtt = ""

        # Print family (and ground truth if available) to stdout
        if not config_dict['c']:
            if config_dict['path']:
                tag_str = format_tag_pairs(tags, av_labels.taxonomy)
            else:
                tag_str = format_tag_pairs(tags)
            sys.stdout.write('%s\t%d\t%s%s%s%s\n' %
                                (name, vt_count, tag_str, gt_family,
                                is_pup_str, vtt))
        else:
            sys.stdout.write('%s\t%s%s%s\n' %
                                (name, fam, gt_family, is_pup_str))
        
        return stats_dict['stats']

    except:
        traceback.print_exc(file=sys.stderr)


def sample_info_func(config_dict):

    # Select hash used to identify sample, by default MD5
    hash_type = config_dict['hash'] if config_dict['hash'] else 'md5'

    gt_dict = {}
    if config_dict['gt']:
        with open(config_dict['gt'], 'r') as gt_fd:
            for line in gt_fd:
                gt_hash, family = map(str, line.strip().split('\t', 1))
                gt_dict[gt_hash] = family

        # Guess type of hash in ground truth file
        hash_type = guess_hash(list(gt_dict.keys())[0])

    # Create AvLabels object
    av_labels = AvLabels(config_dict['tag'], config_dict['exp'], config_dict['tax'],
                         config_dict['av'], config_dict['aliasdetect'])

    stats_dict = {}
    stats_dict['first_token_dict'] = {}
    stats_dict['token_count_map'] = {}
    stats_dict['pair_count_map'] = {}
    stats_dict['avtags_dict'] = {}
    stats_dict['stats'] = {'samples': 0, 'noscans': 0, 'tagged': 0, 'maltagged': 0,
                           'FAM': 0, 'CLASS': 0, 'BEH': 0, 'FILE': 0, 'UNK': 0}

    if config_dict['isdata']:

        # Select output prefix
        out_prefix = script_dir

        vt_all = 1
        
        get_sample_info = av_labels.get_sample_info_lb
        
        # Read JSON line
        vt_rep = json.loads(config_dict['isdata'])

        # Extract sample info
        sample_info = get_sample_info(vt_rep)

        stats_dict['stats'] = labeler(config_dict, sample_info, hash_type, av_labels, stats_dict)

    else:

        # Build list of input files
        # NOTE: duplicate input files are not removed
        ifile_l = []
        if config_dict['vt']:
            ifile_l += config_dict['vt']
            ifile_are_vt = True
        if config_dict['lb']:
            ifile_l += config_dict['lb']
            ifile_are_vt = False
        if config_dict['vtdir']:
            ifile_l += [os.path.join(config_dict['vtdir'], 
                                      f) for f in os.listdir(config_dict['vtdir'])]
            ifile_are_vt = True
        if config_dict['lbdir']:
            ifile_l += [os.path.join(config_dict['lbdir'], 
                                      f) for f in os.listdir(config_dict['lbdir'])]
            ifile_are_vt = False

        # Select correct sample info extraction function
        if not ifile_are_vt:
            get_sample_info = av_labels.get_sample_info_lb
        elif config_dict['vt3']:
            get_sample_info = av_labels.get_sample_info_vt_v3
        else:
            get_sample_info = av_labels.get_sample_info_vt_v2


        # Select output prefix
        out_prefix = os.path.basename(os.path.splitext(ifile_l[0])[0])

        vt_all = 0

        for ifile in ifile_l:

            # Open file
            fd = open(ifile, 'r')

            # Debug info, file processed
            sys.stderr.write('[-] Processing input file %s\n' % ifile)

            # Process all lines in file
            for line in fd:

                # If blank line, skip
                if line == '\n':
                    continue

                # Debug info
                if vt_all % 100 == 0:
                    sys.stderr.write('\r[-] %d JSON read\n' % vt_all)
                    sys.stderr.flush()
                vt_all += 1

                # Read JSON line
                vt_rep = json.loads(line)

                sample_info = get_sample_info(vt_rep)

                stats_dict['stats'] = labeler(config_dict, sample_info, hash_type, av_labels, stats_dict)

            # Close file
            fd.close()
    
    # Debug info
    sys.stderr.write('\r[-] %d JSON read' % vt_all)
    sys.stderr.flush()
    sys.stderr.write('\n')

    # Print statistics
    sys.stderr.write(
            "[-] Samples: %d NoScans: %d NoTags: %d GroundTruth: %d\n" % (
                vt_all, stats_dict['stats']['noscans'], vt_all - stats_dict['stats']['tagged'], 
                len(gt_dict)))

    # If ground truth, print precision, recall, and F1-measure
    if config_dict['gt']:
        precision, recall, fmeasure = \
                    ec.eval_precision_recall_fmeasure(gt_dict,
                                                      stats_dict['first_token_dict'])
        sys.stderr.write(
            "Precision: %.2f\tRecall: %.2f\tF1-Measure: %.2f\n" % \
                          (precision, recall, fmeasure))

    # Output stats
    if config_dict['stats']:
        stats_fd = open("%s.stats" % out_prefix, 'w')
        num_samples = vt_all
        stats_fd.write('Samples: %d\n' % num_samples)
        num_tagged = stats_dict['stats']['tagged']
        frac = float(num_tagged) / float(num_samples) * 100
        stats_fd.write('Tagged (all): %d (%.01f%%)\n' % (num_tagged, frac))
        num_maltagged = stats_dict['stats']['maltagged']
        frac = float(num_maltagged) / float(num_samples) * 100
        stats_fd.write('Tagged (VT>3): %d (%.01f%%)\n' % (num_maltagged, frac))
        for c in ['FILE','CLASS','BEH','FAM','UNK']:
            count = stats_dict['stats'][c]
            frac = float(count) / float(num_maltagged) * 100
            stats_fd.write('%s: %d (%.01f%%)\n' % (c, stats_dict['stats'][c], frac))
        stats_fd.close()

    # Output vendor info
    if config_dict['avtags']:
        avtags_fd = open("%s.avtags" % out_prefix, 'w')
        for t in sorted(stats_dict['avtags_dict'].keys()):
            avtags_fd.write('%s\t' % t)
            pairs = sorted(stats_dict['avtags_dict'][t].items(),
                            key=lambda pair : pair[1],
                            reverse=True)
            for pair in pairs:
                avtags_fd.write('%s|%d,' % (pair[0], pair[1]))
            avtags_fd.write('\n')
        avtags_fd.close()

    # If alias detection, print map
    if config_dict['aliasdetect']:
        # Open alias file
        alias_filename = out_prefix + '.alias'
        alias_fd = open(alias_filename, 'w+')
        # Sort token pairs by number of times they appear together
        sorted_pairs = sorted(
            stats_dict['pair_count_map'].items(), key=itemgetter(1))
        # sorted_pairs = sorted(
        #     pair_count_map.items())

        # Output header line
        alias_fd.write("# t1\tt2\t|t1|\t|t2|\t"
                       "|t1^t2|\t|t1^t2|/|t1|\t|t1^t2|/|t2|\n")
        # Compute token pair statistic and output to alias file
        for (t1, t2), c in sorted_pairs:
            n1 = stats_dict['token_count_map'][t1]
            n2 = stats_dict['token_count_map'][t2]
            if (n1 < n2):
                x = t1
                y = t2
                xn = n1
                yn = n2
            else:
                x = t2
                y = t1
                xn = n2
                yn = n1
            f = float(c) / float(xn)
            finv = float(c) / float(yn)
            alias_fd.write("%s\t%s\t%d\t%d\t%d\t%0.2f\t%0.2f\n" % (
                x, y, xn, yn, c, f, finv))
        # Close alias file
        alias_fd.close()
        sys.stderr.write('[-] Alias data in %s\n' % (alias_filename))

    exit(0)


def parse_args():
    argparser = argparse.ArgumentParser(prog='avclass2_labeler',
        description='''Extracts tags for a set of samples.
            Also calculates precision and recall if ground truth available''')

    argparser.add_argument('-vt', action='append',
        help='file with VT reports '
             '(Can be provided multiple times)')

    argparser.add_argument('-lb', action='append',
        help='file with simplified JSON reports'
             '{md5,sha1,sha256,scan_date,av_labels} '
             '(Can be provided multiple times)')

    argparser.add_argument('-vtdir',
        help='existing directory with VT reports')

    argparser.add_argument('-lbdir',
        help='existing directory with simplified JSON reports')

    argparser.add_argument('-vt3', action='store_true',
        help='input are VT v3 files')

    argparser.add_argument('-gt',
        help='file with ground truth. '
             'If provided it evaluates clustering accuracy. '
             'Prints precision, recall, F1-measure.')

    argparser.add_argument('-vtt',
        help='Include VT tags in the output.',
        action='store_true')

    argparser.add_argument('-tag',
        help='file with tagging rules.',
        default = default_tag_file)

    argparser.add_argument('-tax',
        help='file with taxonomy.',
        default = default_tax_file)

    argparser.add_argument('-exp',
        help='file with expansion rules.',
        default = default_exp_file)

    argparser.add_argument('-av',
        help='file with list of AVs to use')

    argparser.add_argument('-avtags',
        help='extracts tags per av vendor',
        action='store_true')

    argparser.add_argument('-pup',
        action='store_true',
        help='if used each sample is classified as PUP or not')

    argparser.add_argument('-p', '--path',
        help='output.full path for tags',
        action='store_true')

    argparser.add_argument('-hash',
        help='hash used to name samples. Should match ground truth',
        choices=['md5', 'sha1', 'sha256'])

    argparser.add_argument('-c',
        help='Compatibility mode. Outputs results in AVClass format.',
        action='store_true')

    argparser.add_argument('-aliasdetect',
        action='store_true',
        help='if used produce aliases file at end')

    argparser.add_argument('-stats',
                           action='store_true',
                           help='if used produce 1 file '
                                'with stats per category '
                                '(File, Class, '
                                'Behavior, Family, Unclassified)')

    argparser.add_argument('--isdata',
        action='store',
        help='if used it needs parsed input data')
    
    args = argparser.parse_args()
    return args


if __name__ == "__main__":

    args = parse_args()

    config_dict = vars(args)

    if not config_dict['vt'] and not config_dict['lb'] and not config_dict['vtdir'] and not config_dict['lbdir'] and not config_dict['isdata']:
        sys.stderr.write('One of the following 5 arguments is required: '
                         '-vt,-lb,-vtdir,-lbdir, --isdata\n')
        exit(1)

    if (config_dict['vt'] or config_dict['vtdir']) and (config_dict['lb'] or config_dict['lbdir']):
        sys.stderr.write('Use either -vt/-vtdir or -lb/-lbdir. '
                         'Both types of input files cannot be combined.\n')
        exit(1)

    if ((config_dict['vt'] or config_dict['vtdir'] or config_dict['lb'] or config_dict['lbdir']) and config_dict['isdata']):
        sys.stderr.write('\nInput file and input data cannot be entered at the same time.\n')
        exit(1)

    if config_dict['tag']:
        if config_dict['tag'] == '/dev/null':
            sys.stderr.write('[-] Using no tagging rules\n')
        else:
            sys.stderr.write('[-] Using tagging rules in %s\n' % (
                              config_dict['tag']))
    else:
        sys.stderr.write('[-] Using default tagging rules in %s\n' % (
                          default_tag_file))

    if config_dict['tax']:
        if config_dict['tax'] == '/dev/null':
            sys.stderr.write('[-] Using no taxonomy\n')
        else:
            sys.stderr.write('[-] Using taxonomy in %s\n' % (
                              config_dict['tax']))
    else:
        sys.stderr.write('[-] Using default taxonomy in %s\n' % (
                          default_tax_file))

    if config_dict['exp']:
        if config_dict['exp'] == '/dev/null':
            sys.stderr.write('[-] Using no expansion tags\n')
        else:
            sys.stderr.write('[-] Using expansion tags in %s\n' % (
                              config_dict['exp']))
    else:
        sys.stderr.write('[-] Using default expansion tags in %s\n' % (
                          default_exp_file))

    sample_info_func(config_dict)
