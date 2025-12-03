import "pe"
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/



//===SUCCESS===
rule DarkenCode_favorite_FavoriteCode : Favorite Family 
{
    meta:
        description = "Favorite code features"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
    
    strings:
        // standard string hiding
        $ = { C6 45 ?? 3B C6 45 ?? 27 C6 45 ?? 34 C6 45 ?? 75 C6 45 ?? 6B C6 45 ?? 6C C6 45 ?? 3B C6 45 ?? 2F }
        $ = { C6 45 ?? 6F C6 45 ?? 73 C6 45 ?? 73 C6 45 ?? 76 C6 45 ?? 63 C6 45 ?? 65 C6 45 ?? 78 C6 45 ?? 65 }
    
    condition:
        any of them
}
//===SUCCESS===
rule DarkenCode_favorite_FavoriteStrings : Favorite Family
{
    meta:
        description = "Favorite Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-06-24"
        
    strings:
        $string1 = "!QAZ4rfv"
        $file1 = "msupdater.exe"
        $file2 = "FAVORITES.DAT"
        
    condition:
       any of ($string*) or all of ($file*)
}
