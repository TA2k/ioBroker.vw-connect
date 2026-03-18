.class public final Lg11/j;
.super Ll11/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:[[Ljava/util/regex/Pattern;


# instance fields
.field public final a:Lj11/k;

.field public final b:Ljava/util/regex/Pattern;

.field public c:Z

.field public d:Lb11/a;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    filled-new-array {v0, v0}, [Ljava/util/regex/Pattern;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    const-string v2, "^<(?:script|pre|style|textarea)(?:\\s|>|$)"

    .line 7
    .line 8
    const/4 v3, 0x2

    .line 9
    invoke-static {v2, v3}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;I)Ljava/util/regex/Pattern;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    const-string v4, "</(?:script|pre|style|textarea)>"

    .line 14
    .line 15
    invoke-static {v4, v3}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;I)Ljava/util/regex/Pattern;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    filled-new-array {v2, v4}, [Ljava/util/regex/Pattern;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    const-string v4, "^<!--"

    .line 24
    .line 25
    invoke-static {v4}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    const-string v5, "-->"

    .line 30
    .line 31
    invoke-static {v5}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 32
    .line 33
    .line 34
    move-result-object v5

    .line 35
    filled-new-array {v4, v5}, [Ljava/util/regex/Pattern;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    const-string v5, "^<[?]"

    .line 40
    .line 41
    invoke-static {v5}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 42
    .line 43
    .line 44
    move-result-object v5

    .line 45
    const-string v6, "\\?>"

    .line 46
    .line 47
    invoke-static {v6}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 48
    .line 49
    .line 50
    move-result-object v6

    .line 51
    filled-new-array {v5, v6}, [Ljava/util/regex/Pattern;

    .line 52
    .line 53
    .line 54
    move-result-object v5

    .line 55
    const-string v6, "^<![A-Z]"

    .line 56
    .line 57
    invoke-static {v6}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 58
    .line 59
    .line 60
    move-result-object v6

    .line 61
    const-string v7, ">"

    .line 62
    .line 63
    invoke-static {v7}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 64
    .line 65
    .line 66
    move-result-object v7

    .line 67
    filled-new-array {v6, v7}, [Ljava/util/regex/Pattern;

    .line 68
    .line 69
    .line 70
    move-result-object v6

    .line 71
    const-string v7, "^<!\\[CDATA\\["

    .line 72
    .line 73
    invoke-static {v7}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 74
    .line 75
    .line 76
    move-result-object v7

    .line 77
    const-string v8, "\\]\\]>"

    .line 78
    .line 79
    invoke-static {v8}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 80
    .line 81
    .line 82
    move-result-object v8

    .line 83
    filled-new-array {v7, v8}, [Ljava/util/regex/Pattern;

    .line 84
    .line 85
    .line 86
    move-result-object v7

    .line 87
    const-string v8, "^</?(?:address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h1|h2|h3|h4|h5|h6|head|header|hr|html|iframe|legend|li|link|main|menu|menuitem|nav|noframes|ol|optgroup|option|p|param|section|source|summary|table|tbody|td|tfoot|th|thead|title|tr|track|ul)(?:\\s|[/]?[>]|$)"

    .line 88
    .line 89
    invoke-static {v8, v3}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;I)Ljava/util/regex/Pattern;

    .line 90
    .line 91
    .line 92
    move-result-object v8

    .line 93
    filled-new-array {v8, v0}, [Ljava/util/regex/Pattern;

    .line 94
    .line 95
    .line 96
    move-result-object v8

    .line 97
    const-string v9, "^(?:<[A-Za-z][A-Za-z0-9-]*(?:\\s+[a-zA-Z_:][a-zA-Z0-9:._-]*(?:\\s*=\\s*(?:[^\"\'=<>`\\x00-\\x20]+|\'[^\']*\'|\"[^\"]*\"))?)*\\s*/?>|</[A-Za-z][A-Za-z0-9-]*\\s*[>])\\s*$"

    .line 98
    .line 99
    invoke-static {v9, v3}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;I)Ljava/util/regex/Pattern;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    filled-new-array {v3, v0}, [Ljava/util/regex/Pattern;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    move-object v3, v4

    .line 108
    move-object v4, v5

    .line 109
    move-object v5, v6

    .line 110
    move-object v6, v7

    .line 111
    move-object v7, v8

    .line 112
    move-object v8, v0

    .line 113
    filled-new-array/range {v1 .. v8}, [[Ljava/util/regex/Pattern;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    sput-object v0, Lg11/j;->e:[[Ljava/util/regex/Pattern;

    .line 118
    .line 119
    return-void
.end method

.method public constructor <init>(Ljava/util/regex/Pattern;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lj11/k;

    .line 5
    .line 6
    invoke-direct {v0}, Lj11/s;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lg11/j;->a:Lj11/k;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput-boolean v0, p0, Lg11/j;->c:Z

    .line 13
    .line 14
    new-instance v0, Lb11/a;

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x0

    .line 18
    invoke-direct {v0, v2, v1}, Lb11/a;-><init>(BI)V

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Lg11/j;->d:Lb11/a;

    .line 22
    .line 23
    iput-object p1, p0, Lg11/j;->b:Ljava/util/regex/Pattern;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final a(Lk11/b;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lg11/j;->d:Lb11/a;

    .line 2
    .line 3
    iget-object p1, p1, Lk11/b;->a:Ljava/lang/CharSequence;

    .line 4
    .line 5
    iget-object v1, v0, Lb11/a;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    iget v2, v0, Lb11/a;->e:I

    .line 10
    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    const/16 v2, 0xa

    .line 14
    .line 15
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    :cond_0
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    iget v1, v0, Lb11/a;->e:I

    .line 22
    .line 23
    const/4 v2, 0x1

    .line 24
    add-int/2addr v1, v2

    .line 25
    iput v1, v0, Lb11/a;->e:I

    .line 26
    .line 27
    iget-object v0, p0, Lg11/j;->b:Ljava/util/regex/Pattern;

    .line 28
    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    invoke-virtual {v0, p1}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-virtual {p1}, Ljava/util/regex/Matcher;->find()Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-eqz p1, :cond_1

    .line 40
    .line 41
    iput-boolean v2, p0, Lg11/j;->c:Z

    .line 42
    .line 43
    :cond_1
    return-void
.end method

.method public final e()V
    .locals 2

    .line 1
    iget-object v0, p0, Lg11/j;->d:Lb11/a;

    .line 2
    .line 3
    iget-object v0, v0, Lb11/a;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object v1, p0, Lg11/j;->a:Lj11/k;

    .line 12
    .line 13
    iput-object v0, v1, Lj11/k;->g:Ljava/lang/String;

    .line 14
    .line 15
    const/4 v0, 0x0

    .line 16
    iput-object v0, p0, Lg11/j;->d:Lb11/a;

    .line 17
    .line 18
    return-void
.end method

.method public final f()Lj11/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lg11/j;->a:Lj11/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final i(Lg11/g;)Lc9/h;
    .locals 1

    .line 1
    iget-boolean v0, p0, Lg11/j;->c:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    iget-boolean v0, p1, Lg11/g;->i:Z

    .line 7
    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    iget-object p0, p0, Lg11/j;->b:Ljava/util/regex/Pattern;

    .line 11
    .line 12
    if-nez p0, :cond_1

    .line 13
    .line 14
    :goto_0
    const/4 p0, 0x0

    .line 15
    return-object p0

    .line 16
    :cond_1
    iget p0, p1, Lg11/g;->c:I

    .line 17
    .line 18
    invoke-static {p0}, Lc9/h;->a(I)Lc9/h;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
