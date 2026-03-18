.class public final Lz9/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final m:Lly0/n;

.field public static final n:Lly0/n;

.field public static final o:Lly0/n;

.field public static final p:Lly0/n;

.field public static final q:Lly0/n;

.field public static final r:Lly0/n;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/util/ArrayList;

.field public final c:Ljava/lang/String;

.field public final d:Llx0/q;

.field public final e:Llx0/q;

.field public final f:Ljava/lang/Object;

.field public g:Z

.field public final h:Ljava/lang/Object;

.field public final i:Ljava/lang/Object;

.field public final j:Ljava/lang/Object;

.field public final k:Llx0/q;

.field public final l:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lly0/n;

    .line 2
    .line 3
    const-string v1, "^[a-zA-Z]+[+\\w\\-.]*:"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lly0/n;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lz9/r;->m:Lly0/n;

    .line 9
    .line 10
    new-instance v0, Lly0/n;

    .line 11
    .line 12
    const-string v1, "\\{(.+?)\\}"

    .line 13
    .line 14
    invoke-direct {v0, v1}, Lly0/n;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lz9/r;->n:Lly0/n;

    .line 18
    .line 19
    new-instance v0, Lly0/n;

    .line 20
    .line 21
    const-string v1, "http[s]?://"

    .line 22
    .line 23
    invoke-direct {v0, v1}, Lly0/n;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Lz9/r;->o:Lly0/n;

    .line 27
    .line 28
    new-instance v0, Lly0/n;

    .line 29
    .line 30
    const-string v1, ".*"

    .line 31
    .line 32
    invoke-direct {v0, v1}, Lly0/n;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sput-object v0, Lz9/r;->p:Lly0/n;

    .line 36
    .line 37
    new-instance v0, Lly0/n;

    .line 38
    .line 39
    const-string v1, "([^/]*?|)"

    .line 40
    .line 41
    invoke-direct {v0, v1}, Lly0/n;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    sput-object v0, Lz9/r;->q:Lly0/n;

    .line 45
    .line 46
    new-instance v0, Lly0/n;

    .line 47
    .line 48
    const-string v1, "^[^?#]+\\?([^#]*).*"

    .line 49
    .line 50
    invoke-direct {v0, v1}, Lly0/n;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    sput-object v0, Lz9/r;->r:Lly0/n;

    .line 54
    .line 55
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz9/r;->a:Ljava/lang/String;

    .line 5
    .line 6
    new-instance v0, Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lz9/r;->b:Ljava/util/ArrayList;

    .line 12
    .line 13
    new-instance v1, Lz9/p;

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    invoke-direct {v1, p0, v2}, Lz9/p;-><init>(Lz9/r;I)V

    .line 17
    .line 18
    .line 19
    invoke-static {v1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    iput-object v1, p0, Lz9/r;->d:Llx0/q;

    .line 24
    .line 25
    new-instance v1, Lz9/p;

    .line 26
    .line 27
    const/4 v2, 0x1

    .line 28
    invoke-direct {v1, p0, v2}, Lz9/p;-><init>(Lz9/r;I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    iput-object v1, p0, Lz9/r;->e:Llx0/q;

    .line 36
    .line 37
    sget-object v1, Llx0/j;->f:Llx0/j;

    .line 38
    .line 39
    new-instance v2, Lz9/p;

    .line 40
    .line 41
    const/4 v3, 0x2

    .line 42
    invoke-direct {v2, p0, v3}, Lz9/p;-><init>(Lz9/r;I)V

    .line 43
    .line 44
    .line 45
    invoke-static {v1, v2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    iput-object v2, p0, Lz9/r;->f:Ljava/lang/Object;

    .line 50
    .line 51
    new-instance v2, Lz9/p;

    .line 52
    .line 53
    const/4 v3, 0x3

    .line 54
    invoke-direct {v2, p0, v3}, Lz9/p;-><init>(Lz9/r;I)V

    .line 55
    .line 56
    .line 57
    invoke-static {v1, v2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    iput-object v2, p0, Lz9/r;->h:Ljava/lang/Object;

    .line 62
    .line 63
    new-instance v2, Lz9/p;

    .line 64
    .line 65
    const/4 v3, 0x4

    .line 66
    invoke-direct {v2, p0, v3}, Lz9/p;-><init>(Lz9/r;I)V

    .line 67
    .line 68
    .line 69
    invoke-static {v1, v2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    iput-object v2, p0, Lz9/r;->i:Ljava/lang/Object;

    .line 74
    .line 75
    new-instance v2, Lz9/p;

    .line 76
    .line 77
    const/4 v3, 0x5

    .line 78
    invoke-direct {v2, p0, v3}, Lz9/p;-><init>(Lz9/r;I)V

    .line 79
    .line 80
    .line 81
    invoke-static {v1, v2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    iput-object v1, p0, Lz9/r;->j:Ljava/lang/Object;

    .line 86
    .line 87
    new-instance v1, Lz9/p;

    .line 88
    .line 89
    const/4 v2, 0x6

    .line 90
    invoke-direct {v1, p0, v2}, Lz9/p;-><init>(Lz9/r;I)V

    .line 91
    .line 92
    .line 93
    invoke-static {v1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    iput-object v1, p0, Lz9/r;->k:Llx0/q;

    .line 98
    .line 99
    new-instance v1, Lz9/p;

    .line 100
    .line 101
    const/4 v2, 0x7

    .line 102
    invoke-direct {v1, p0, v2}, Lz9/p;-><init>(Lz9/r;I)V

    .line 103
    .line 104
    .line 105
    invoke-static {v1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 106
    .line 107
    .line 108
    new-instance v1, Ljava/lang/StringBuilder;

    .line 109
    .line 110
    const-string v2, "^"

    .line 111
    .line 112
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    sget-object v2, Lz9/r;->m:Lly0/n;

    .line 116
    .line 117
    iget-object v2, v2, Lly0/n;->d:Ljava/util/regex/Pattern;

    .line 118
    .line 119
    invoke-virtual {v2, p1}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 120
    .line 121
    .line 122
    move-result-object v2

    .line 123
    invoke-virtual {v2}, Ljava/util/regex/Matcher;->find()Z

    .line 124
    .line 125
    .line 126
    move-result v2

    .line 127
    if-nez v2, :cond_0

    .line 128
    .line 129
    sget-object v2, Lz9/r;->o:Lly0/n;

    .line 130
    .line 131
    iget-object v2, v2, Lly0/n;->d:Ljava/util/regex/Pattern;

    .line 132
    .line 133
    invoke-virtual {v2}, Ljava/util/regex/Pattern;->pattern()Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object v2

    .line 137
    const-string v3, "pattern(...)"

    .line 138
    .line 139
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    :cond_0
    const-string v2, "(\\?|#|$)"

    .line 146
    .line 147
    invoke-static {v2}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 148
    .line 149
    .line 150
    move-result-object v2

    .line 151
    const-string v3, "compile(...)"

    .line 152
    .line 153
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v2, p1}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 157
    .line 158
    .line 159
    move-result-object v2

    .line 160
    const-string v3, "matcher(...)"

    .line 161
    .line 162
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    const/4 v3, 0x0

    .line 166
    invoke-static {v2, v3, p1}, Ltm0/d;->c(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Lly0/l;

    .line 167
    .line 168
    .line 169
    move-result-object v2

    .line 170
    if-eqz v2, :cond_2

    .line 171
    .line 172
    invoke-virtual {v2}, Lly0/l;->b()Lgy0/j;

    .line 173
    .line 174
    .line 175
    move-result-object v2

    .line 176
    iget v2, v2, Lgy0/h;->d:I

    .line 177
    .line 178
    invoke-virtual {p1, v3, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object p1

    .line 182
    const-string v2, "substring(...)"

    .line 183
    .line 184
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    invoke-static {p1, v0, v1}, Lz9/r;->a(Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/StringBuilder;)V

    .line 188
    .line 189
    .line 190
    sget-object p1, Lz9/r;->p:Lly0/n;

    .line 191
    .line 192
    iget-object p1, p1, Lly0/n;->d:Ljava/util/regex/Pattern;

    .line 193
    .line 194
    invoke-virtual {p1, v1}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 195
    .line 196
    .line 197
    move-result-object p1

    .line 198
    invoke-virtual {p1}, Ljava/util/regex/Matcher;->find()Z

    .line 199
    .line 200
    .line 201
    move-result p1

    .line 202
    if-nez p1, :cond_1

    .line 203
    .line 204
    sget-object p1, Lz9/r;->q:Lly0/n;

    .line 205
    .line 206
    iget-object p1, p1, Lly0/n;->d:Ljava/util/regex/Pattern;

    .line 207
    .line 208
    invoke-virtual {p1, v1}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 209
    .line 210
    .line 211
    move-result-object p1

    .line 212
    invoke-virtual {p1}, Ljava/util/regex/Matcher;->find()Z

    .line 213
    .line 214
    .line 215
    move-result p1

    .line 216
    if-nez p1, :cond_1

    .line 217
    .line 218
    const/4 v3, 0x1

    .line 219
    :cond_1
    iput-boolean v3, p0, Lz9/r;->l:Z

    .line 220
    .line 221
    const-string p1, "($|(\\?(.)*)|(#(.)*))"

    .line 222
    .line 223
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 224
    .line 225
    .line 226
    :cond_2
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 227
    .line 228
    .line 229
    move-result-object p1

    .line 230
    const-string v0, "toString(...)"

    .line 231
    .line 232
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 233
    .line 234
    .line 235
    invoke-static {p1}, Lz9/r;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object p1

    .line 239
    iput-object p1, p0, Lz9/r;->c:Ljava/lang/String;

    .line 240
    .line 241
    return-void
.end method

.method public static a(Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/StringBuilder;)V
    .locals 6

    .line 1
    sget-object v0, Lz9/r;->n:Lly0/n;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object v0, v0, Lly0/n;->d:Ljava/util/regex/Pattern;

    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    const-string v1, "matcher(...)"

    .line 13
    .line 14
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    invoke-static {v0, v1, p0}, Ltm0/d;->c(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Lly0/l;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    :goto_0
    const-string v2, "quote(...)"

    .line 23
    .line 24
    const-string v3, "substring(...)"

    .line 25
    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    iget-object v4, v0, Lly0/l;->c:Lly0/k;

    .line 29
    .line 30
    const/4 v5, 0x1

    .line 31
    invoke-virtual {v4, v5}, Lly0/k;->e(I)Lly0/i;

    .line 32
    .line 33
    .line 34
    move-result-object v4

    .line 35
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    iget-object v4, v4, Lly0/i;->a:Ljava/lang/String;

    .line 39
    .line 40
    invoke-virtual {p1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0}, Lly0/l;->b()Lgy0/j;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    iget v4, v4, Lgy0/h;->d:I

    .line 48
    .line 49
    if-le v4, v1, :cond_0

    .line 50
    .line 51
    invoke-virtual {v0}, Lly0/l;->b()Lgy0/j;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    iget v4, v4, Lgy0/h;->d:I

    .line 56
    .line 57
    invoke-virtual {p0, v1, v4}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    invoke-static {v1}, Ljava/util/regex/Pattern;->quote(Ljava/lang/String;)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    :cond_0
    sget-object v1, Lz9/r;->q:Lly0/n;

    .line 75
    .line 76
    iget-object v1, v1, Lly0/n;->d:Ljava/util/regex/Pattern;

    .line 77
    .line 78
    invoke-virtual {v1}, Ljava/util/regex/Pattern;->pattern()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    const-string v2, "pattern(...)"

    .line 83
    .line 84
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {v0}, Lly0/l;->b()Lgy0/j;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    iget v1, v1, Lgy0/h;->e:I

    .line 95
    .line 96
    add-int/2addr v1, v5

    .line 97
    invoke-virtual {v0}, Lly0/l;->d()Lly0/l;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    goto :goto_0

    .line 102
    :cond_1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 103
    .line 104
    .line 105
    move-result p1

    .line 106
    if-ge v1, p1, :cond_2

    .line 107
    .line 108
    invoke-virtual {p0, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    invoke-static {p0}, Ljava/util/regex/Pattern;->quote(Ljava/lang/String;)Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    :cond_2
    return-void
.end method

.method public static g(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Lz9/i;)V
    .locals 1

    .line 1
    if-eqz p3, :cond_0

    .line 2
    .line 3
    iget-object p3, p3, Lz9/i;->a:Lz9/g0;

    .line 4
    .line 5
    const-string v0, "key"

    .line 6
    .line 7
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p3, p2}, Lz9/g0;->d(Ljava/lang/String;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    invoke-virtual {p3, p0, p1, p2}, Lz9/g0;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    invoke-static {p1, p2, p0}, Lkp/v;->e(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public static h(Ljava/lang/String;)Ljava/lang/String;
    .locals 4

    .line 1
    const-string v0, "\\Q"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-static {p0, v0, v1}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    const-string v2, ".*"

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    const-string v0, "\\E"

    .line 13
    .line 14
    invoke-static {p0, v0, v1}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const-string v0, "\\E.*\\Q"

    .line 21
    .line 22
    invoke-static {v1, p0, v2, v0}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :cond_0
    const-string v0, "\\.\\*"

    .line 28
    .line 29
    invoke-static {p0, v0, v1}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-eqz v3, :cond_1

    .line 34
    .line 35
    invoke-static {v1, p0, v0, v2}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    :cond_1
    return-object p0
.end method


# virtual methods
.method public final b(Landroid/net/Uri;)I
    .locals 1

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/net/Uri;->getPathSegments()Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    iget-object p0, p0, Lz9/r;->a:Ljava/lang/String;

    .line 8
    .line 9
    invoke-static {p0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    const-string v0, "parse(...)"

    .line 14
    .line 15
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0}, Landroid/net/Uri;->getPathSegments()Ljava/util/List;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p1, Ljava/lang/Iterable;

    .line 23
    .line 24
    check-cast p0, Ljava/lang/Iterable;

    .line 25
    .line 26
    invoke-static {p1, p0}, Lmx0/q;->O(Ljava/lang/Iterable;Ljava/lang/Iterable;)Ljava/util/Set;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-interface {p0}, Ljava/util/Set;->size()I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    return p0

    .line 35
    :cond_0
    const/4 p0, 0x0

    .line 36
    return p0
.end method

.method public final c()Ljava/util/ArrayList;
    .locals 3

    .line 1
    iget-object v0, p0, Lz9/r;->f:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ljava/util/Map;

    .line 8
    .line 9
    invoke-interface {v0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Ljava/lang/Iterable;

    .line 14
    .line 15
    new-instance v1, Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 18
    .line 19
    .line 20
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-eqz v2, :cond_0

    .line 29
    .line 30
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    check-cast v2, Lz9/q;

    .line 35
    .line 36
    iget-object v2, v2, Lz9/q;->b:Ljava/util/ArrayList;

    .line 37
    .line 38
    invoke-static {v2, v1}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    iget-object v0, p0, Lz9/r;->b:Ljava/util/ArrayList;

    .line 43
    .line 44
    invoke-static {v1, v0}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    iget-object p0, p0, Lz9/r;->i:Ljava/lang/Object;

    .line 49
    .line 50
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    check-cast p0, Ljava/util/List;

    .line 55
    .line 56
    check-cast p0, Ljava/lang/Iterable;

    .line 57
    .line 58
    invoke-static {p0, v0}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0
.end method

.method public final d(Landroid/net/Uri;Ljava/util/LinkedHashMap;)Landroid/os/Bundle;
    .locals 7

    .line 1
    const-string v0, "deepLink"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "arguments"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lz9/r;->d:Llx0/q;

    .line 12
    .line 13
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Lly0/n;

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    if-eqz v0, :cond_9

    .line 21
    .line 22
    invoke-virtual {p1}, Landroid/net/Uri;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-virtual {v0, v2}, Lly0/n;->c(Ljava/lang/String;)Lly0/l;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    if-nez v0, :cond_0

    .line 31
    .line 32
    goto/16 :goto_3

    .line 33
    .line 34
    :cond_0
    const/4 v2, 0x0

    .line 35
    new-array v3, v2, [Llx0/l;

    .line 36
    .line 37
    invoke-static {v3, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    check-cast v3, [Llx0/l;

    .line 42
    .line 43
    invoke-static {v3}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 44
    .line 45
    .line 46
    move-result-object v3

    .line 47
    invoke-virtual {p0, v0, v3, p2}, Lz9/r;->e(Lly0/l;Landroid/os/Bundle;Ljava/util/Map;)Z

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-nez v0, :cond_1

    .line 52
    .line 53
    goto/16 :goto_3

    .line 54
    .line 55
    :cond_1
    iget-object v0, p0, Lz9/r;->e:Llx0/q;

    .line 56
    .line 57
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    check-cast v0, Ljava/lang/Boolean;

    .line 62
    .line 63
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    if-eqz v0, :cond_2

    .line 68
    .line 69
    invoke-virtual {p0, p1, v3, p2}, Lz9/r;->f(Landroid/net/Uri;Landroid/os/Bundle;Ljava/util/Map;)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-nez v0, :cond_2

    .line 74
    .line 75
    goto/16 :goto_3

    .line 76
    .line 77
    :cond_2
    invoke-virtual {p1}, Landroid/net/Uri;->getFragment()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    iget-object v0, p0, Lz9/r;->k:Llx0/q;

    .line 82
    .line 83
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    check-cast v0, Lly0/n;

    .line 88
    .line 89
    if-eqz v0, :cond_7

    .line 90
    .line 91
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    invoke-virtual {v0, p1}, Lly0/n;->c(Ljava/lang/String;)Lly0/l;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    if-nez p1, :cond_3

    .line 100
    .line 101
    goto :goto_2

    .line 102
    :cond_3
    iget-object p0, p0, Lz9/r;->i:Ljava/lang/Object;

    .line 103
    .line 104
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    check-cast p0, Ljava/util/List;

    .line 109
    .line 110
    check-cast p0, Ljava/lang/Iterable;

    .line 111
    .line 112
    new-instance v0, Ljava/util/ArrayList;

    .line 113
    .line 114
    const/16 v4, 0xa

    .line 115
    .line 116
    invoke-static {p0, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 117
    .line 118
    .line 119
    move-result v4

    .line 120
    invoke-direct {v0, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 121
    .line 122
    .line 123
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 128
    .line 129
    .line 130
    move-result v4

    .line 131
    if-eqz v4, :cond_7

    .line 132
    .line 133
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v4

    .line 137
    add-int/lit8 v5, v2, 0x1

    .line 138
    .line 139
    if-ltz v2, :cond_6

    .line 140
    .line 141
    check-cast v4, Ljava/lang/String;

    .line 142
    .line 143
    iget-object v2, p1, Lly0/l;->c:Lly0/k;

    .line 144
    .line 145
    invoke-virtual {v2, v5}, Lly0/k;->e(I)Lly0/i;

    .line 146
    .line 147
    .line 148
    move-result-object v2

    .line 149
    if-eqz v2, :cond_4

    .line 150
    .line 151
    iget-object v2, v2, Lly0/i;->a:Ljava/lang/String;

    .line 152
    .line 153
    invoke-static {v2}, Landroid/net/Uri;->decode(Ljava/lang/String;)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v2

    .line 157
    const-string v6, "decode(...)"

    .line 158
    .line 159
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    goto :goto_1

    .line 163
    :cond_4
    move-object v2, v1

    .line 164
    :goto_1
    if-nez v2, :cond_5

    .line 165
    .line 166
    const-string v2, ""

    .line 167
    .line 168
    :cond_5
    invoke-virtual {p2, v4}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v6

    .line 172
    check-cast v6, Lz9/i;

    .line 173
    .line 174
    :try_start_0
    invoke-static {v3, v4, v2, v6}, Lz9/r;->g(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Lz9/i;)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 175
    .line 176
    .line 177
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 178
    .line 179
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    move v2, v5

    .line 183
    goto :goto_0

    .line 184
    :cond_6
    invoke-static {}, Ljp/k1;->r()V

    .line 185
    .line 186
    .line 187
    throw v1

    .line 188
    :catch_0
    :cond_7
    :goto_2
    new-instance p0, Lca/i;

    .line 189
    .line 190
    const/4 p1, 0x1

    .line 191
    invoke-direct {p0, p1, v3}, Lca/i;-><init>(ILandroid/os/Bundle;)V

    .line 192
    .line 193
    .line 194
    invoke-static {p2, p0}, Ljb0/b;->e(Ljava/util/Map;Lay0/k;)Ljava/util/ArrayList;

    .line 195
    .line 196
    .line 197
    move-result-object p0

    .line 198
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 199
    .line 200
    .line 201
    move-result p0

    .line 202
    if-nez p0, :cond_8

    .line 203
    .line 204
    goto :goto_3

    .line 205
    :cond_8
    return-object v3

    .line 206
    :cond_9
    :goto_3
    return-object v1
.end method

.method public final e(Lly0/l;Landroid/os/Bundle;Ljava/util/Map;)Z
    .locals 6

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    const/16 v1, 0xa

    .line 4
    .line 5
    iget-object p0, p0, Lz9/r;->b:Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-static {p0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    const/4 v1, 0x0

    .line 19
    move v2, v1

    .line 20
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    if-eqz v3, :cond_3

    .line 25
    .line 26
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    add-int/lit8 v4, v2, 0x1

    .line 31
    .line 32
    const/4 v5, 0x0

    .line 33
    if-ltz v2, :cond_2

    .line 34
    .line 35
    check-cast v3, Ljava/lang/String;

    .line 36
    .line 37
    iget-object v2, p1, Lly0/l;->c:Lly0/k;

    .line 38
    .line 39
    invoke-virtual {v2, v4}, Lly0/k;->e(I)Lly0/i;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    if-eqz v2, :cond_0

    .line 44
    .line 45
    iget-object v2, v2, Lly0/i;->a:Ljava/lang/String;

    .line 46
    .line 47
    invoke-static {v2}, Landroid/net/Uri;->decode(Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v5

    .line 51
    const-string v2, "decode(...)"

    .line 52
    .line 53
    invoke-static {v5, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    :cond_0
    if-nez v5, :cond_1

    .line 57
    .line 58
    const-string v5, ""

    .line 59
    .line 60
    :cond_1
    invoke-interface {p3, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    check-cast v2, Lz9/i;

    .line 65
    .line 66
    :try_start_0
    invoke-static {p2, v3, v5, v2}, Lz9/r;->g(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Lz9/i;)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 67
    .line 68
    .line 69
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move v2, v4

    .line 75
    goto :goto_0

    .line 76
    :catch_0
    return v1

    .line 77
    :cond_2
    invoke-static {}, Ljp/k1;->r()V

    .line 78
    .line 79
    .line 80
    throw v5

    .line 81
    :cond_3
    const/4 p0, 0x1

    .line 82
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    instance-of v0, p1, Lz9/r;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    check-cast p1, Lz9/r;

    .line 9
    .line 10
    iget-object p1, p1, Lz9/r;->a:Ljava/lang/String;

    .line 11
    .line 12
    iget-object p0, p0, Lz9/r;->a:Ljava/lang/String;

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-eqz p0, :cond_1

    .line 19
    .line 20
    const/4 p0, 0x1

    .line 21
    return p0

    .line 22
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 23
    return p0
.end method

.method public final f(Landroid/net/Uri;Landroid/os/Bundle;Ljava/util/Map;)Z
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    iget-object v2, v0, Lz9/r;->f:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    check-cast v2, Ljava/util/Map;

    .line 12
    .line 13
    invoke-interface {v2}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    if-eqz v3, :cond_10

    .line 26
    .line 27
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    check-cast v3, Ljava/util/Map$Entry;

    .line 32
    .line 33
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    check-cast v5, Ljava/lang/String;

    .line 38
    .line 39
    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    check-cast v3, Lz9/q;

    .line 44
    .line 45
    move-object/from16 v6, p1

    .line 46
    .line 47
    invoke-virtual {v6, v5}, Landroid/net/Uri;->getQueryParameters(Ljava/lang/String;)Ljava/util/List;

    .line 48
    .line 49
    .line 50
    move-result-object v5

    .line 51
    iget-boolean v7, v0, Lz9/r;->g:Z

    .line 52
    .line 53
    if-eqz v7, :cond_0

    .line 54
    .line 55
    invoke-virtual {v6}, Landroid/net/Uri;->getQuery()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v7

    .line 59
    if-eqz v7, :cond_0

    .line 60
    .line 61
    invoke-virtual {v6}, Landroid/net/Uri;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v8

    .line 65
    invoke-virtual {v7, v8}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v8

    .line 69
    if-nez v8, :cond_0

    .line 70
    .line 71
    invoke-static {v7}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 72
    .line 73
    .line 74
    move-result-object v5

    .line 75
    :cond_0
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 76
    .line 77
    const/4 v8, 0x0

    .line 78
    new-array v9, v8, [Llx0/l;

    .line 79
    .line 80
    invoke-static {v9, v8}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v9

    .line 84
    check-cast v9, [Llx0/l;

    .line 85
    .line 86
    invoke-static {v9}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 87
    .line 88
    .line 89
    move-result-object v9

    .line 90
    iget-object v10, v3, Lz9/q;->b:Ljava/util/ArrayList;

    .line 91
    .line 92
    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 93
    .line 94
    .line 95
    move-result-object v10

    .line 96
    :cond_1
    :goto_1
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 97
    .line 98
    .line 99
    move-result v11

    .line 100
    if-eqz v11, :cond_3

    .line 101
    .line 102
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v11

    .line 106
    check-cast v11, Ljava/lang/String;

    .line 107
    .line 108
    invoke-interface {v1, v11}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v13

    .line 112
    check-cast v13, Lz9/i;

    .line 113
    .line 114
    if-eqz v13, :cond_2

    .line 115
    .line 116
    iget-object v12, v13, Lz9/i;->a:Lz9/g0;

    .line 117
    .line 118
    goto :goto_2

    .line 119
    :cond_2
    const/4 v12, 0x0

    .line 120
    :goto_2
    instance-of v14, v12, Lz9/f;

    .line 121
    .line 122
    if-eqz v14, :cond_1

    .line 123
    .line 124
    iget-boolean v13, v13, Lz9/i;->c:Z

    .line 125
    .line 126
    if-nez v13, :cond_1

    .line 127
    .line 128
    check-cast v12, Lz9/f;

    .line 129
    .line 130
    invoke-virtual {v12}, Lz9/f;->h()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v13

    .line 134
    invoke-virtual {v12, v9, v11, v13}, Lz9/g0;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    goto :goto_1

    .line 138
    :cond_3
    check-cast v5, Ljava/lang/Iterable;

    .line 139
    .line 140
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 141
    .line 142
    .line 143
    move-result-object v5

    .line 144
    :cond_4
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 145
    .line 146
    .line 147
    move-result v10

    .line 148
    if-eqz v10, :cond_f

    .line 149
    .line 150
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v10

    .line 154
    check-cast v10, Ljava/lang/String;

    .line 155
    .line 156
    iget-object v11, v3, Lz9/q;->a:Ljava/lang/String;

    .line 157
    .line 158
    if-eqz v11, :cond_6

    .line 159
    .line 160
    invoke-static {v11}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 161
    .line 162
    .line 163
    move-result-object v11

    .line 164
    const-string v13, "compile(...)"

    .line 165
    .line 166
    invoke-static {v11, v13}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    const-string v13, "input"

    .line 170
    .line 171
    invoke-static {v10, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {v11, v10}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 175
    .line 176
    .line 177
    move-result-object v11

    .line 178
    const-string v13, "matcher(...)"

    .line 179
    .line 180
    invoke-static {v11, v13}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v11}, Ljava/util/regex/Matcher;->matches()Z

    .line 184
    .line 185
    .line 186
    move-result v13

    .line 187
    if-nez v13, :cond_5

    .line 188
    .line 189
    goto :goto_3

    .line 190
    :cond_5
    new-instance v13, Lly0/l;

    .line 191
    .line 192
    invoke-direct {v13, v11, v10}, Lly0/l;-><init>(Ljava/util/regex/Matcher;Ljava/lang/CharSequence;)V

    .line 193
    .line 194
    .line 195
    goto :goto_4

    .line 196
    :cond_6
    :goto_3
    const/4 v13, 0x0

    .line 197
    :goto_4
    if-nez v13, :cond_7

    .line 198
    .line 199
    return v8

    .line 200
    :cond_7
    iget-object v10, v3, Lz9/q;->b:Ljava/util/ArrayList;

    .line 201
    .line 202
    new-instance v11, Ljava/util/ArrayList;

    .line 203
    .line 204
    const/16 v14, 0xa

    .line 205
    .line 206
    invoke-static {v10, v14}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 207
    .line 208
    .line 209
    move-result v14

    .line 210
    invoke-direct {v11, v14}, Ljava/util/ArrayList;-><init>(I)V

    .line 211
    .line 212
    .line 213
    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 214
    .line 215
    .line 216
    move-result-object v10

    .line 217
    move v14, v8

    .line 218
    :goto_5
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 219
    .line 220
    .line 221
    move-result v15

    .line 222
    if-eqz v15, :cond_4

    .line 223
    .line 224
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v15

    .line 228
    const/16 v16, 0x1

    .line 229
    .line 230
    add-int/lit8 v4, v14, 0x1

    .line 231
    .line 232
    if-ltz v14, :cond_e

    .line 233
    .line 234
    check-cast v15, Ljava/lang/String;

    .line 235
    .line 236
    iget-object v14, v13, Lly0/l;->c:Lly0/k;

    .line 237
    .line 238
    invoke-virtual {v14, v4}, Lly0/k;->e(I)Lly0/i;

    .line 239
    .line 240
    .line 241
    move-result-object v14

    .line 242
    if-eqz v14, :cond_8

    .line 243
    .line 244
    iget-object v14, v14, Lly0/i;->a:Ljava/lang/String;

    .line 245
    .line 246
    goto :goto_6

    .line 247
    :cond_8
    const/4 v14, 0x0

    .line 248
    :goto_6
    if-nez v14, :cond_9

    .line 249
    .line 250
    const-string v14, ""

    .line 251
    .line 252
    :cond_9
    invoke-interface {v1, v15}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    move-result-object v17

    .line 256
    move-object/from16 v8, v17

    .line 257
    .line 258
    check-cast v8, Lz9/i;

    .line 259
    .line 260
    const/16 v17, 0x0

    .line 261
    .line 262
    :try_start_0
    const-string v12, "key"

    .line 263
    .line 264
    invoke-static {v15, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 265
    .line 266
    .line 267
    invoke-virtual {v9, v15}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 268
    .line 269
    .line 270
    move-result v12

    .line 271
    if-nez v12, :cond_a

    .line 272
    .line 273
    invoke-static {v9, v15, v14, v8}, Lz9/r;->g(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;Lz9/i;)V

    .line 274
    .line 275
    .line 276
    goto :goto_9

    .line 277
    :cond_a
    invoke-virtual {v9, v15}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 278
    .line 279
    .line 280
    move-result v12

    .line 281
    if-nez v12, :cond_b

    .line 282
    .line 283
    move/from16 v8, v16

    .line 284
    .line 285
    goto :goto_8

    .line 286
    :cond_b
    if-eqz v8, :cond_d

    .line 287
    .line 288
    iget-object v8, v8, Lz9/i;->a:Lz9/g0;

    .line 289
    .line 290
    invoke-virtual {v8, v15, v9}, Lz9/g0;->a(Ljava/lang/String;Landroid/os/Bundle;)Ljava/lang/Object;

    .line 291
    .line 292
    .line 293
    move-result-object v12

    .line 294
    invoke-virtual {v9, v15}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 295
    .line 296
    .line 297
    move-result v18

    .line 298
    if-eqz v18, :cond_c

    .line 299
    .line 300
    invoke-virtual {v8, v12, v14}, Lz9/g0;->c(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 301
    .line 302
    .line 303
    move-result-object v12

    .line 304
    invoke-virtual {v8, v9, v15, v12}, Lz9/g0;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Object;)V

    .line 305
    .line 306
    .line 307
    goto :goto_7

    .line 308
    :cond_c
    new-instance v8, Ljava/lang/IllegalArgumentException;

    .line 309
    .line 310
    const-string v12, "There is no previous value in this savedState."

    .line 311
    .line 312
    invoke-direct {v8, v12}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 313
    .line 314
    .line 315
    throw v8

    .line 316
    :cond_d
    :goto_7
    const/4 v8, 0x0

    .line 317
    :goto_8
    invoke-static {v8}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 318
    .line 319
    .line 320
    move-result-object v8
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 321
    goto :goto_a

    .line 322
    :catch_0
    :goto_9
    move-object v8, v7

    .line 323
    :goto_a
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 324
    .line 325
    .line 326
    move v14, v4

    .line 327
    const/4 v8, 0x0

    .line 328
    goto :goto_5

    .line 329
    :cond_e
    const/16 v17, 0x0

    .line 330
    .line 331
    invoke-static {}, Ljp/k1;->r()V

    .line 332
    .line 333
    .line 334
    throw v17

    .line 335
    :cond_f
    move-object/from16 v4, p2

    .line 336
    .line 337
    invoke-virtual {v4, v9}, Landroid/os/Bundle;->putAll(Landroid/os/Bundle;)V

    .line 338
    .line 339
    .line 340
    goto/16 :goto_0

    .line 341
    .line 342
    :cond_10
    const/16 v16, 0x1

    .line 343
    .line 344
    return v16
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lz9/r;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    mul-int/lit16 p0, p0, 0x3c1

    .line 8
    .line 9
    return p0
.end method
