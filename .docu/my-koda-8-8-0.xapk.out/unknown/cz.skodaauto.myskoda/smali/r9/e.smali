.class public final Lr9/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll9/j;


# static fields
.field public static final e:Ljava/util/regex/Pattern;

.field public static final f:Ljava/util/regex/Pattern;

.field public static final g:Ljava/util/regex/Pattern;

.field public static final h:Ljava/util/regex/Pattern;

.field public static final i:Ljava/util/regex/Pattern;

.field public static final j:Ljava/util/regex/Pattern;

.field public static final k:Ljava/util/regex/Pattern;

.field public static final l:Lr9/d;


# instance fields
.field public final d:Lorg/xmlpull/v1/XmlPullParserFactory;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-string v0, "^([0-9][0-9]+):([0-9][0-9]):([0-9][0-9])(?:(\\.[0-9]+)|:([0-9][0-9])(?:\\.([0-9]+))?)?$"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lr9/e;->e:Ljava/util/regex/Pattern;

    .line 8
    .line 9
    const-string v0, "^([0-9]+(?:\\.[0-9]+)?)(h|m|s|ms|f|t)$"

    .line 10
    .line 11
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lr9/e;->f:Ljava/util/regex/Pattern;

    .line 16
    .line 17
    const-string v0, "^(([0-9]*.)?[0-9]+)(px|em|%)$"

    .line 18
    .line 19
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lr9/e;->g:Ljava/util/regex/Pattern;

    .line 24
    .line 25
    const-string v0, "^([-+]?\\d+\\.?\\d*?)%$"

    .line 26
    .line 27
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Lr9/e;->h:Ljava/util/regex/Pattern;

    .line 32
    .line 33
    const-string v0, "^([-+]?\\d+\\.?\\d*?)% ([-+]?\\d+\\.?\\d*?)%$"

    .line 34
    .line 35
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    sput-object v0, Lr9/e;->i:Ljava/util/regex/Pattern;

    .line 40
    .line 41
    const-string v0, "^([-+]?\\d+\\.?\\d*?)px ([-+]?\\d+\\.?\\d*?)px$"

    .line 42
    .line 43
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    sput-object v0, Lr9/e;->j:Ljava/util/regex/Pattern;

    .line 48
    .line 49
    const-string v0, "^(\\d+) (\\d+)$"

    .line 50
    .line 51
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sput-object v0, Lr9/e;->k:Ljava/util/regex/Pattern;

    .line 56
    .line 57
    new-instance v0, Lr9/d;

    .line 58
    .line 59
    const/high16 v1, 0x41f00000    # 30.0f

    .line 60
    .line 61
    const/4 v2, 0x1

    .line 62
    invoke-direct {v0, v1, v2, v2}, Lr9/d;-><init>(FII)V

    .line 63
    .line 64
    .line 65
    sput-object v0, Lr9/e;->l:Lr9/d;

    .line 66
    .line 67
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    invoke-static {}, Lorg/xmlpull/v1/XmlPullParserFactory;->newInstance()Lorg/xmlpull/v1/XmlPullParserFactory;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Lr9/e;->d:Lorg/xmlpull/v1/XmlPullParserFactory;

    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    invoke-virtual {v0, p0}, Lorg/xmlpull/v1/XmlPullParserFactory;->setNamespaceAware(Z)V
    :try_end_0
    .catch Lorg/xmlpull/v1/XmlPullParserException; {:try_start_0 .. :try_end_0} :catch_0

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :catch_0
    move-exception p0

    .line 16
    new-instance v0, Ljava/lang/RuntimeException;

    .line 17
    .line 18
    const-string v1, "Couldn\'t create XmlPullParserFactory instance"

    .line 19
    .line 20
    invoke-direct {v0, v1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 21
    .line 22
    .line 23
    throw v0
.end method

.method public static a(Lr9/g;)Lr9/g;
    .locals 0

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    new-instance p0, Lr9/g;

    .line 4
    .line 5
    invoke-direct {p0}, Lr9/g;-><init>()V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-object p0
.end method

.method public static c(Ljava/lang/String;)Z
    .locals 1

    .line 1
    const-string v0, "tt"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    const-string v0, "head"

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    const-string v0, "body"

    .line 18
    .line 19
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    const-string v0, "div"

    .line 26
    .line 27
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-nez v0, :cond_1

    .line 32
    .line 33
    const-string v0, "p"

    .line 34
    .line 35
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-nez v0, :cond_1

    .line 40
    .line 41
    const-string v0, "span"

    .line 42
    .line 43
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-nez v0, :cond_1

    .line 48
    .line 49
    const-string v0, "br"

    .line 50
    .line 51
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-nez v0, :cond_1

    .line 56
    .line 57
    const-string v0, "style"

    .line 58
    .line 59
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-nez v0, :cond_1

    .line 64
    .line 65
    const-string v0, "styling"

    .line 66
    .line 67
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    if-nez v0, :cond_1

    .line 72
    .line 73
    const-string v0, "layout"

    .line 74
    .line 75
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v0

    .line 79
    if-nez v0, :cond_1

    .line 80
    .line 81
    const-string v0, "region"

    .line 82
    .line 83
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v0

    .line 87
    if-nez v0, :cond_1

    .line 88
    .line 89
    const-string v0, "metadata"

    .line 90
    .line 91
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    if-nez v0, :cond_1

    .line 96
    .line 97
    const-string v0, "image"

    .line 98
    .line 99
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v0

    .line 103
    if-nez v0, :cond_1

    .line 104
    .line 105
    const-string v0, "data"

    .line 106
    .line 107
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v0

    .line 111
    if-nez v0, :cond_1

    .line 112
    .line 113
    const-string v0, "information"

    .line 114
    .line 115
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result p0

    .line 119
    if-eqz p0, :cond_0

    .line 120
    .line 121
    goto :goto_0

    .line 122
    :cond_0
    const/4 p0, 0x0

    .line 123
    return p0

    .line 124
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 125
    return p0
.end method

.method public static d(Lorg/xmlpull/v1/XmlPullParser;)I
    .locals 8

    .line 1
    const-string v0, "Invalid cell resolution "

    .line 2
    .line 3
    const-string v1, "http://www.w3.org/ns/ttml#parameter"

    .line 4
    .line 5
    const-string v2, "cellResolution"

    .line 6
    .line 7
    invoke-interface {p0, v1, v2}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const/16 v1, 0xf

    .line 12
    .line 13
    if-nez p0, :cond_0

    .line 14
    .line 15
    return v1

    .line 16
    :cond_0
    sget-object v2, Lr9/e;->k:Ljava/util/regex/Pattern;

    .line 17
    .line 18
    invoke-virtual {v2, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    invoke-virtual {v2}, Ljava/util/regex/Matcher;->matches()Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    const-string v4, "Ignoring malformed cell resolution: "

    .line 27
    .line 28
    const-string v5, "TtmlParser"

    .line 29
    .line 30
    if-nez v3, :cond_1

    .line 31
    .line 32
    invoke-virtual {v4, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-static {v5, p0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    return v1

    .line 40
    :cond_1
    const/4 v3, 0x1

    .line 41
    :try_start_0
    invoke-virtual {v2, v3}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v6

    .line 45
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    invoke-static {v6}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 49
    .line 50
    .line 51
    move-result v6

    .line 52
    const/4 v7, 0x2

    .line 53
    invoke-virtual {v2, v7}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    invoke-static {v2}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    if-eqz v6, :cond_2

    .line 65
    .line 66
    if-eqz v2, :cond_2

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_2
    const/4 v3, 0x0

    .line 70
    :goto_0
    new-instance v7, Ljava/lang/StringBuilder;

    .line 71
    .line 72
    invoke-direct {v7, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v7, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    const-string v0, " "

    .line 79
    .line 80
    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {v7, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    invoke-static {v3, v0}, Lw7/a;->d(ZLjava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 91
    .line 92
    .line 93
    return v2

    .line 94
    :catch_0
    invoke-virtual {v4, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    invoke-static {v5, p0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    return v1
.end method

.method public static e(Ljava/lang/String;Lr9/g;)V
    .locals 7

    .line 1
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, "\\s+"

    .line 4
    .line 5
    const/4 v1, -0x1

    .line 6
    invoke-virtual {p0, v0, v1}, Ljava/lang/String;->split(Ljava/lang/String;I)[Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    array-length v2, v0

    .line 11
    const/4 v3, 0x2

    .line 12
    sget-object v4, Lr9/e;->g:Ljava/util/regex/Pattern;

    .line 13
    .line 14
    const/4 v5, 0x1

    .line 15
    if-ne v2, v5, :cond_0

    .line 16
    .line 17
    invoke-virtual {v4, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    array-length v2, v0

    .line 23
    if-ne v2, v3, :cond_5

    .line 24
    .line 25
    aget-object v0, v0, v5

    .line 26
    .line 27
    invoke-virtual {v4, v0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    const-string v2, "TtmlParser"

    .line 32
    .line 33
    const-string v4, "Multiple values in fontSize attribute. Picking the second value for vertical font size and ignoring the first."

    .line 34
    .line 35
    invoke-static {v2, v4}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    :goto_0
    invoke-virtual {v0}, Ljava/util/regex/Matcher;->matches()Z

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    const-string v4, "\'."

    .line 43
    .line 44
    if-eqz v2, :cond_4

    .line 45
    .line 46
    const/4 p0, 0x3

    .line 47
    invoke-virtual {v0, p0}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 55
    .line 56
    .line 57
    move-result v6

    .line 58
    sparse-switch v6, :sswitch_data_0

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :sswitch_0
    const-string v6, "px"

    .line 63
    .line 64
    invoke-virtual {v2, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v6

    .line 68
    if-nez v6, :cond_1

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_1
    move v1, v3

    .line 72
    goto :goto_1

    .line 73
    :sswitch_1
    const-string v6, "em"

    .line 74
    .line 75
    invoke-virtual {v2, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v6

    .line 79
    if-nez v6, :cond_2

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_2
    move v1, v5

    .line 83
    goto :goto_1

    .line 84
    :sswitch_2
    const-string v6, "%"

    .line 85
    .line 86
    invoke-virtual {v2, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v6

    .line 90
    if-nez v6, :cond_3

    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_3
    const/4 v1, 0x0

    .line 94
    :goto_1
    packed-switch v1, :pswitch_data_0

    .line 95
    .line 96
    .line 97
    new-instance p0, Ll9/f;

    .line 98
    .line 99
    const-string p1, "Invalid unit for fontSize: \'"

    .line 100
    .line 101
    invoke-static {p1, v2, v4}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    throw p0

    .line 109
    :pswitch_0
    iput v5, p1, Lr9/g;->j:I

    .line 110
    .line 111
    goto :goto_2

    .line 112
    :pswitch_1
    iput v3, p1, Lr9/g;->j:I

    .line 113
    .line 114
    goto :goto_2

    .line 115
    :pswitch_2
    iput p0, p1, Lr9/g;->j:I

    .line 116
    .line 117
    :goto_2
    invoke-virtual {v0, v5}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 122
    .line 123
    .line 124
    invoke-static {p0}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 125
    .line 126
    .line 127
    move-result p0

    .line 128
    iput p0, p1, Lr9/g;->k:F

    .line 129
    .line 130
    return-void

    .line 131
    :cond_4
    new-instance p1, Ll9/f;

    .line 132
    .line 133
    const-string v0, "Invalid expression for fontSize: \'"

    .line 134
    .line 135
    invoke-static {v0, p0, v4}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    invoke-direct {p1, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    throw p1

    .line 143
    :cond_5
    new-instance p0, Ll9/f;

    .line 144
    .line 145
    new-instance p1, Ljava/lang/StringBuilder;

    .line 146
    .line 147
    const-string v1, "Invalid number of entries for fontSize: "

    .line 148
    .line 149
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    array-length v0, v0

    .line 153
    const-string v1, "."

    .line 154
    .line 155
    invoke-static {v0, v1, p1}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    throw p0

    .line 163
    :sswitch_data_0
    .sparse-switch
        0x25 -> :sswitch_2
        0xca8 -> :sswitch_1
        0xe08 -> :sswitch_0
    .end sparse-switch

    .line 164
    .line 165
    .line 166
    .line 167
    .line 168
    .line 169
    .line 170
    .line 171
    .line 172
    .line 173
    .line 174
    .line 175
    .line 176
    .line 177
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static f(Lorg/xmlpull/v1/XmlPullParser;)Lr9/d;
    .locals 7

    .line 1
    const-string v0, "frameRate"

    .line 2
    .line 3
    const-string v1, "http://www.w3.org/ns/ttml#parameter"

    .line 4
    .line 5
    invoke-interface {p0, v1, v0}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-static {v0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/16 v0, 0x1e

    .line 17
    .line 18
    :goto_0
    const-string v2, "frameRateMultiplier"

    .line 19
    .line 20
    invoke-interface {p0, v1, v2}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    if-eqz v2, :cond_2

    .line 25
    .line 26
    sget-object v3, Lw7/w;->a:Ljava/lang/String;

    .line 27
    .line 28
    const/4 v3, -0x1

    .line 29
    const-string v4, " "

    .line 30
    .line 31
    invoke-virtual {v2, v4, v3}, Ljava/lang/String;->split(Ljava/lang/String;I)[Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    array-length v3, v2

    .line 36
    const/4 v4, 0x2

    .line 37
    const/4 v5, 0x0

    .line 38
    const/4 v6, 0x1

    .line 39
    if-ne v3, v4, :cond_1

    .line 40
    .line 41
    move v3, v6

    .line 42
    goto :goto_1

    .line 43
    :cond_1
    move v3, v5

    .line 44
    :goto_1
    const-string v4, "frameRateMultiplier doesn\'t have 2 parts"

    .line 45
    .line 46
    invoke-static {v3, v4}, Lw7/a;->d(ZLjava/lang/String;)V

    .line 47
    .line 48
    .line 49
    aget-object v3, v2, v5

    .line 50
    .line 51
    invoke-static {v3}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 52
    .line 53
    .line 54
    move-result v3

    .line 55
    int-to-float v3, v3

    .line 56
    aget-object v2, v2, v6

    .line 57
    .line 58
    invoke-static {v2}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    int-to-float v2, v2

    .line 63
    div-float/2addr v3, v2

    .line 64
    goto :goto_2

    .line 65
    :cond_2
    const/high16 v3, 0x3f800000    # 1.0f

    .line 66
    .line 67
    :goto_2
    sget-object v2, Lr9/e;->l:Lr9/d;

    .line 68
    .line 69
    iget v4, v2, Lr9/d;->b:I

    .line 70
    .line 71
    const-string v5, "subFrameRate"

    .line 72
    .line 73
    invoke-interface {p0, v1, v5}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v5

    .line 77
    if-eqz v5, :cond_3

    .line 78
    .line 79
    invoke-static {v5}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 80
    .line 81
    .line 82
    move-result v4

    .line 83
    :cond_3
    iget v2, v2, Lr9/d;->c:I

    .line 84
    .line 85
    const-string v5, "tickRate"

    .line 86
    .line 87
    invoke-interface {p0, v1, v5}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    if-eqz p0, :cond_4

    .line 92
    .line 93
    invoke-static {p0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 94
    .line 95
    .line 96
    move-result v2

    .line 97
    :cond_4
    new-instance p0, Lr9/d;

    .line 98
    .line 99
    int-to-float v0, v0

    .line 100
    mul-float/2addr v0, v3

    .line 101
    invoke-direct {p0, v0, v4, v2}, Lr9/d;-><init>(FII)V

    .line 102
    .line 103
    .line 104
    return-object p0
.end method

.method public static h(Lorg/xmlpull/v1/XmlPullParser;Ljava/util/HashMap;ILb8/i;Ljava/util/HashMap;Ljava/util/HashMap;)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    :cond_0
    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 8
    .line 9
    .line 10
    const-string v3, "style"

    .line 11
    .line 12
    invoke-static {v0, v3}, Lw7/a;->v(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    .line 13
    .line 14
    .line 15
    move-result v4

    .line 16
    const/4 v5, -0x1

    .line 17
    const/4 v6, 0x0

    .line 18
    if-eqz v4, :cond_6

    .line 19
    .line 20
    invoke-static {v0, v3}, Lw7/a;->r(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    new-instance v4, Lr9/g;

    .line 25
    .line 26
    invoke-direct {v4}, Lr9/g;-><init>()V

    .line 27
    .line 28
    .line 29
    invoke-static {v0, v4}, Lr9/e;->j(Lorg/xmlpull/v1/XmlPullParser;Lr9/g;)Lr9/g;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    if-eqz v3, :cond_2

    .line 34
    .line 35
    invoke-virtual {v3}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    invoke-virtual {v3}, Ljava/lang/String;->isEmpty()Z

    .line 40
    .line 41
    .line 42
    move-result v7

    .line 43
    if-eqz v7, :cond_1

    .line 44
    .line 45
    new-array v3, v6, [Ljava/lang/String;

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    sget-object v7, Lw7/w;->a:Ljava/lang/String;

    .line 49
    .line 50
    const-string v7, "\\s+"

    .line 51
    .line 52
    invoke-virtual {v3, v7, v5}, Ljava/lang/String;->split(Ljava/lang/String;I)[Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    :goto_0
    array-length v5, v3

    .line 57
    :goto_1
    if-ge v6, v5, :cond_2

    .line 58
    .line 59
    aget-object v7, v3, v6

    .line 60
    .line 61
    invoke-virtual {v1, v7}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v7

    .line 65
    check-cast v7, Lr9/g;

    .line 66
    .line 67
    invoke-virtual {v4, v7}, Lr9/g;->a(Lr9/g;)V

    .line 68
    .line 69
    .line 70
    add-int/lit8 v6, v6, 0x1

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_2
    iget-object v3, v4, Lr9/g;->l:Ljava/lang/String;

    .line 74
    .line 75
    if-eqz v3, :cond_3

    .line 76
    .line 77
    invoke-virtual {v1, v3, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    :cond_3
    move/from16 v4, p2

    .line 81
    .line 82
    :cond_4
    move-object/from16 v5, p4

    .line 83
    .line 84
    :cond_5
    :goto_2
    move-object/from16 v9, p5

    .line 85
    .line 86
    goto/16 :goto_11

    .line 87
    .line 88
    :cond_6
    const-string v4, "region"

    .line 89
    .line 90
    invoke-static {v0, v4}, Lw7/a;->v(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    .line 91
    .line 92
    .line 93
    move-result v4

    .line 94
    const-string v7, "id"

    .line 95
    .line 96
    if-eqz v4, :cond_19

    .line 97
    .line 98
    invoke-static {v0, v7}, Lw7/a;->r(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object v9

    .line 102
    if-nez v9, :cond_7

    .line 103
    .line 104
    :goto_3
    move/from16 v4, p2

    .line 105
    .line 106
    const/4 v8, 0x0

    .line 107
    goto/16 :goto_f

    .line 108
    .line 109
    :cond_7
    const-string v7, "origin"

    .line 110
    .line 111
    invoke-static {v0, v7}, Lw7/a;->r(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v7

    .line 115
    if-nez v7, :cond_8

    .line 116
    .line 117
    invoke-static {v0, v3}, Lw7/a;->r(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v8

    .line 121
    if-eqz v8, :cond_8

    .line 122
    .line 123
    invoke-virtual {v1, v8}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v8

    .line 127
    check-cast v8, Lr9/g;

    .line 128
    .line 129
    if-eqz v8, :cond_8

    .line 130
    .line 131
    iget-object v7, v8, Lr9/g;->t:Ljava/lang/String;

    .line 132
    .line 133
    :cond_8
    const/4 v8, 0x2

    .line 134
    const/4 v10, 0x1

    .line 135
    const-string v11, "Ignoring region with missing tts:extent: "

    .line 136
    .line 137
    sget-object v12, Lr9/e;->j:Ljava/util/regex/Pattern;

    .line 138
    .line 139
    sget-object v13, Lr9/e;->i:Ljava/util/regex/Pattern;

    .line 140
    .line 141
    const/high16 v14, 0x42c80000    # 100.0f

    .line 142
    .line 143
    const-string v15, "TtmlParser"

    .line 144
    .line 145
    if-eqz v7, :cond_c

    .line 146
    .line 147
    invoke-virtual {v13, v7}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 148
    .line 149
    .line 150
    move-result-object v4

    .line 151
    invoke-virtual {v12, v7}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 152
    .line 153
    .line 154
    move-result-object v5

    .line 155
    invoke-virtual {v4}, Ljava/util/regex/Matcher;->matches()Z

    .line 156
    .line 157
    .line 158
    move-result v18

    .line 159
    const-string v6, "Ignoring region with malformed origin: "

    .line 160
    .line 161
    if-eqz v18, :cond_9

    .line 162
    .line 163
    :try_start_0
    invoke-virtual {v4, v10}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object v5

    .line 167
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 168
    .line 169
    .line 170
    invoke-static {v5}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 171
    .line 172
    .line 173
    move-result v5

    .line 174
    div-float/2addr v5, v14

    .line 175
    invoke-virtual {v4, v8}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v4

    .line 179
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 180
    .line 181
    .line 182
    invoke-static {v4}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 183
    .line 184
    .line 185
    move-result v4
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 186
    div-float/2addr v4, v14

    .line 187
    move/from16 v18, v14

    .line 188
    .line 189
    goto :goto_4

    .line 190
    :catch_0
    invoke-virtual {v6, v7}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object v3

    .line 194
    invoke-static {v15, v3}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    goto :goto_3

    .line 198
    :cond_9
    invoke-virtual {v5}, Ljava/util/regex/Matcher;->matches()Z

    .line 199
    .line 200
    .line 201
    move-result v4

    .line 202
    if-eqz v4, :cond_b

    .line 203
    .line 204
    if-nez v2, :cond_a

    .line 205
    .line 206
    invoke-virtual {v11, v7}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 207
    .line 208
    .line 209
    move-result-object v3

    .line 210
    invoke-static {v15, v3}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    goto :goto_3

    .line 214
    :cond_a
    :try_start_1
    invoke-virtual {v5, v10}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object v4

    .line 218
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 219
    .line 220
    .line 221
    invoke-static {v4}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 222
    .line 223
    .line 224
    move-result v4

    .line 225
    invoke-virtual {v5, v8}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object v5

    .line 229
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 230
    .line 231
    .line 232
    invoke-static {v5}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 233
    .line 234
    .line 235
    move-result v5

    .line 236
    int-to-float v4, v4

    .line 237
    move/from16 v18, v14

    .line 238
    .line 239
    iget v14, v2, Lb8/i;->b:I

    .line 240
    .line 241
    int-to-float v14, v14

    .line 242
    div-float/2addr v4, v14

    .line 243
    int-to-float v5, v5

    .line 244
    iget v6, v2, Lb8/i;->c:I
    :try_end_1
    .catch Ljava/lang/NumberFormatException; {:try_start_1 .. :try_end_1} :catch_1

    .line 245
    .line 246
    int-to-float v6, v6

    .line 247
    div-float/2addr v5, v6

    .line 248
    move/from16 v19, v5

    .line 249
    .line 250
    move v5, v4

    .line 251
    move/from16 v4, v19

    .line 252
    .line 253
    goto :goto_4

    .line 254
    :catch_1
    invoke-virtual {v6, v7}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 255
    .line 256
    .line 257
    move-result-object v3

    .line 258
    invoke-static {v15, v3}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 259
    .line 260
    .line 261
    goto/16 :goto_3

    .line 262
    .line 263
    :cond_b
    const-string v3, "Ignoring region with unsupported origin: "

    .line 264
    .line 265
    invoke-virtual {v3, v7}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 266
    .line 267
    .line 268
    move-result-object v3

    .line 269
    invoke-static {v15, v3}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 270
    .line 271
    .line 272
    goto/16 :goto_3

    .line 273
    .line 274
    :cond_c
    move/from16 v18, v14

    .line 275
    .line 276
    const/4 v4, 0x0

    .line 277
    move v5, v4

    .line 278
    :goto_4
    const-string v6, "extent"

    .line 279
    .line 280
    invoke-static {v0, v6}, Lw7/a;->r(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Ljava/lang/String;

    .line 281
    .line 282
    .line 283
    move-result-object v6

    .line 284
    if-nez v6, :cond_d

    .line 285
    .line 286
    invoke-static {v0, v3}, Lw7/a;->r(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Ljava/lang/String;

    .line 287
    .line 288
    .line 289
    move-result-object v3

    .line 290
    if-eqz v3, :cond_d

    .line 291
    .line 292
    invoke-virtual {v1, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 293
    .line 294
    .line 295
    move-result-object v3

    .line 296
    check-cast v3, Lr9/g;

    .line 297
    .line 298
    if-eqz v3, :cond_d

    .line 299
    .line 300
    iget-object v6, v3, Lr9/g;->u:Ljava/lang/String;

    .line 301
    .line 302
    :cond_d
    const/high16 v3, 0x3f800000    # 1.0f

    .line 303
    .line 304
    if-eqz v6, :cond_11

    .line 305
    .line 306
    invoke-virtual {v13, v6}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 307
    .line 308
    .line 309
    move-result-object v13

    .line 310
    invoke-virtual {v12, v6}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 311
    .line 312
    .line 313
    move-result-object v6

    .line 314
    invoke-virtual {v13}, Ljava/util/regex/Matcher;->matches()Z

    .line 315
    .line 316
    .line 317
    move-result v12

    .line 318
    const-string v14, "Ignoring region with malformed extent: "

    .line 319
    .line 320
    if-eqz v12, :cond_e

    .line 321
    .line 322
    :try_start_2
    invoke-virtual {v13, v10}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 323
    .line 324
    .line 325
    move-result-object v6

    .line 326
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 327
    .line 328
    .line 329
    invoke-static {v6}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 330
    .line 331
    .line 332
    move-result v6

    .line 333
    div-float v6, v6, v18

    .line 334
    .line 335
    invoke-virtual {v13, v8}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 336
    .line 337
    .line 338
    move-result-object v11

    .line 339
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 340
    .line 341
    .line 342
    invoke-static {v11}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 343
    .line 344
    .line 345
    move-result v7
    :try_end_2
    .catch Ljava/lang/NumberFormatException; {:try_start_2 .. :try_end_2} :catch_2

    .line 346
    div-float v7, v7, v18

    .line 347
    .line 348
    goto :goto_5

    .line 349
    :catch_2
    invoke-static {v14, v7, v15}, Lvj/b;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 350
    .line 351
    .line 352
    goto/16 :goto_3

    .line 353
    .line 354
    :cond_e
    invoke-virtual {v6}, Ljava/util/regex/Matcher;->matches()Z

    .line 355
    .line 356
    .line 357
    move-result v12

    .line 358
    if-eqz v12, :cond_10

    .line 359
    .line 360
    if-nez v2, :cond_f

    .line 361
    .line 362
    invoke-static {v11, v7, v15}, Lvj/b;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 363
    .line 364
    .line 365
    goto/16 :goto_3

    .line 366
    .line 367
    :cond_f
    :try_start_3
    invoke-virtual {v6, v10}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 368
    .line 369
    .line 370
    move-result-object v11

    .line 371
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 372
    .line 373
    .line 374
    invoke-static {v11}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 375
    .line 376
    .line 377
    move-result v11

    .line 378
    invoke-virtual {v6, v8}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 379
    .line 380
    .line 381
    move-result-object v6

    .line 382
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 383
    .line 384
    .line 385
    invoke-static {v6}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 386
    .line 387
    .line 388
    move-result v6

    .line 389
    int-to-float v11, v11

    .line 390
    iget v12, v2, Lb8/i;->b:I

    .line 391
    .line 392
    int-to-float v12, v12

    .line 393
    div-float/2addr v11, v12

    .line 394
    int-to-float v6, v6

    .line 395
    iget v7, v2, Lb8/i;->c:I
    :try_end_3
    .catch Ljava/lang/NumberFormatException; {:try_start_3 .. :try_end_3} :catch_2

    .line 396
    .line 397
    int-to-float v7, v7

    .line 398
    div-float v7, v6, v7

    .line 399
    .line 400
    move v6, v11

    .line 401
    :goto_5
    move v14, v6

    .line 402
    move v15, v7

    .line 403
    goto :goto_6

    .line 404
    :cond_10
    const-string v3, "Ignoring region with unsupported extent: "

    .line 405
    .line 406
    invoke-static {v3, v7, v15}, Lvj/b;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 407
    .line 408
    .line 409
    goto/16 :goto_3

    .line 410
    .line 411
    :cond_11
    move v14, v3

    .line 412
    move v15, v14

    .line 413
    :goto_6
    const-string v6, "displayAlign"

    .line 414
    .line 415
    invoke-static {v0, v6}, Lw7/a;->r(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Ljava/lang/String;

    .line 416
    .line 417
    .line 418
    move-result-object v6

    .line 419
    if-eqz v6, :cond_14

    .line 420
    .line 421
    invoke-static {v6}, Lkp/g9;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 422
    .line 423
    .line 424
    move-result-object v6

    .line 425
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 426
    .line 427
    .line 428
    const-string v7, "center"

    .line 429
    .line 430
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 431
    .line 432
    .line 433
    move-result v7

    .line 434
    if-nez v7, :cond_13

    .line 435
    .line 436
    const-string v7, "after"

    .line 437
    .line 438
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 439
    .line 440
    .line 441
    move-result v6

    .line 442
    if-nez v6, :cond_12

    .line 443
    .line 444
    goto :goto_8

    .line 445
    :cond_12
    add-float/2addr v4, v15

    .line 446
    move v11, v4

    .line 447
    move v13, v8

    .line 448
    :goto_7
    move/from16 v4, p2

    .line 449
    .line 450
    goto :goto_9

    .line 451
    :cond_13
    const/high16 v6, 0x40000000    # 2.0f

    .line 452
    .line 453
    div-float v6, v15, v6

    .line 454
    .line 455
    add-float/2addr v4, v6

    .line 456
    move v11, v4

    .line 457
    move v13, v10

    .line 458
    goto :goto_7

    .line 459
    :cond_14
    :goto_8
    move v11, v4

    .line 460
    const/4 v13, 0x0

    .line 461
    goto :goto_7

    .line 462
    :goto_9
    int-to-float v6, v4

    .line 463
    div-float/2addr v3, v6

    .line 464
    const-string v6, "writingMode"

    .line 465
    .line 466
    invoke-static {v0, v6}, Lw7/a;->r(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Ljava/lang/String;

    .line 467
    .line 468
    .line 469
    move-result-object v6

    .line 470
    if-eqz v6, :cond_18

    .line 471
    .line 472
    invoke-static {v6}, Lkp/g9;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 473
    .line 474
    .line 475
    move-result-object v6

    .line 476
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 477
    .line 478
    .line 479
    invoke-virtual {v6}, Ljava/lang/String;->hashCode()I

    .line 480
    .line 481
    .line 482
    move-result v7

    .line 483
    sparse-switch v7, :sswitch_data_0

    .line 484
    .line 485
    .line 486
    :goto_a
    const/16 v17, -0x1

    .line 487
    .line 488
    goto :goto_b

    .line 489
    :sswitch_0
    const-string v7, "tbrl"

    .line 490
    .line 491
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 492
    .line 493
    .line 494
    move-result v6

    .line 495
    if-nez v6, :cond_15

    .line 496
    .line 497
    goto :goto_a

    .line 498
    :cond_15
    move/from16 v17, v8

    .line 499
    .line 500
    goto :goto_b

    .line 501
    :sswitch_1
    const-string v7, "tblr"

    .line 502
    .line 503
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 504
    .line 505
    .line 506
    move-result v6

    .line 507
    if-nez v6, :cond_16

    .line 508
    .line 509
    goto :goto_a

    .line 510
    :cond_16
    move/from16 v17, v10

    .line 511
    .line 512
    goto :goto_b

    .line 513
    :sswitch_2
    const-string v7, "tb"

    .line 514
    .line 515
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 516
    .line 517
    .line 518
    move-result v6

    .line 519
    if-nez v6, :cond_17

    .line 520
    .line 521
    goto :goto_a

    .line 522
    :cond_17
    const/16 v17, 0x0

    .line 523
    .line 524
    :goto_b
    packed-switch v17, :pswitch_data_0

    .line 525
    .line 526
    .line 527
    goto :goto_d

    .line 528
    :pswitch_0
    move/from16 v18, v10

    .line 529
    .line 530
    goto :goto_e

    .line 531
    :goto_c
    :pswitch_1
    move/from16 v18, v8

    .line 532
    .line 533
    goto :goto_e

    .line 534
    :cond_18
    :goto_d
    const/high16 v8, -0x80000000

    .line 535
    .line 536
    goto :goto_c

    .line 537
    :goto_e
    new-instance v8, Lr9/f;

    .line 538
    .line 539
    const/4 v12, 0x0

    .line 540
    const/16 v16, 0x1

    .line 541
    .line 542
    move/from16 v17, v3

    .line 543
    .line 544
    move v10, v5

    .line 545
    invoke-direct/range {v8 .. v18}, Lr9/f;-><init>(Ljava/lang/String;FFIIFFIFI)V

    .line 546
    .line 547
    .line 548
    :goto_f
    if-eqz v8, :cond_4

    .line 549
    .line 550
    iget-object v3, v8, Lr9/f;->a:Ljava/lang/String;

    .line 551
    .line 552
    move-object/from16 v5, p4

    .line 553
    .line 554
    invoke-virtual {v5, v3, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 555
    .line 556
    .line 557
    goto/16 :goto_2

    .line 558
    .line 559
    :cond_19
    move/from16 v4, p2

    .line 560
    .line 561
    move-object/from16 v5, p4

    .line 562
    .line 563
    const-string v3, "metadata"

    .line 564
    .line 565
    invoke-static {v0, v3}, Lw7/a;->v(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    .line 566
    .line 567
    .line 568
    move-result v6

    .line 569
    if-eqz v6, :cond_5

    .line 570
    .line 571
    :cond_1a
    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 572
    .line 573
    .line 574
    const-string v6, "image"

    .line 575
    .line 576
    invoke-static {v0, v6}, Lw7/a;->v(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    .line 577
    .line 578
    .line 579
    move-result v6

    .line 580
    if-eqz v6, :cond_1b

    .line 581
    .line 582
    invoke-static {v0, v7}, Lw7/a;->r(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Ljava/lang/String;

    .line 583
    .line 584
    .line 585
    move-result-object v6

    .line 586
    if-eqz v6, :cond_1b

    .line 587
    .line 588
    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->nextText()Ljava/lang/String;

    .line 589
    .line 590
    .line 591
    move-result-object v8

    .line 592
    move-object/from16 v9, p5

    .line 593
    .line 594
    invoke-virtual {v9, v6, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 595
    .line 596
    .line 597
    goto :goto_10

    .line 598
    :cond_1b
    move-object/from16 v9, p5

    .line 599
    .line 600
    :goto_10
    invoke-static {v0, v3}, Lw7/a;->t(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    .line 601
    .line 602
    .line 603
    move-result v6

    .line 604
    if-eqz v6, :cond_1a

    .line 605
    .line 606
    :goto_11
    const-string v3, "head"

    .line 607
    .line 608
    invoke-static {v0, v3}, Lw7/a;->t(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    .line 609
    .line 610
    .line 611
    move-result v3

    .line 612
    if-eqz v3, :cond_0

    .line 613
    .line 614
    return-void

    .line 615
    :sswitch_data_0
    .sparse-switch
        0xe6e -> :sswitch_2
        0x363874 -> :sswitch_1
        0x363928 -> :sswitch_0
    .end sparse-switch

    .line 616
    .line 617
    .line 618
    .line 619
    .line 620
    .line 621
    .line 622
    .line 623
    .line 624
    .line 625
    .line 626
    .line 627
    .line 628
    .line 629
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static i(Lorg/xmlpull/v1/XmlPullParser;Lr9/c;Ljava/util/HashMap;Lr9/d;)Lr9/c;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v11, p1

    .line 4
    .line 5
    move-object/from16 v1, p3

    .line 6
    .line 7
    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeCount()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    const/4 v3, 0x0

    .line 12
    invoke-static {v0, v3}, Lr9/e;->j(Lorg/xmlpull/v1/XmlPullParser;Lr9/g;)Lr9/g;

    .line 13
    .line 14
    .line 15
    move-result-object v7

    .line 16
    const-string v6, ""

    .line 17
    .line 18
    move-object v10, v3

    .line 19
    move-object v9, v6

    .line 20
    const/4 v6, 0x0

    .line 21
    const-wide v12, -0x7fffffffffffffffL    # -4.9E-324

    .line 22
    .line 23
    .line 24
    .line 25
    .line 26
    const-wide v14, -0x7fffffffffffffffL    # -4.9E-324

    .line 27
    .line 28
    .line 29
    .line 30
    .line 31
    const-wide v16, -0x7fffffffffffffffL    # -4.9E-324

    .line 32
    .line 33
    .line 34
    .line 35
    .line 36
    :goto_0
    if-ge v6, v2, :cond_9

    .line 37
    .line 38
    const-wide v18, -0x7fffffffffffffffL    # -4.9E-324

    .line 39
    .line 40
    .line 41
    .line 42
    .line 43
    invoke-interface {v0, v6}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeName(I)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    invoke-interface {v0, v6}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(I)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v5

    .line 51
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v4}, Ljava/lang/String;->hashCode()I

    .line 55
    .line 56
    .line 57
    move-result v20

    .line 58
    sparse-switch v20, :sswitch_data_0

    .line 59
    .line 60
    .line 61
    :goto_1
    const/4 v4, -0x1

    .line 62
    goto :goto_2

    .line 63
    :sswitch_0
    const-string v8, "backgroundImage"

    .line 64
    .line 65
    invoke-virtual {v4, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v4

    .line 69
    if-nez v4, :cond_0

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_0
    const/4 v4, 0x5

    .line 73
    goto :goto_2

    .line 74
    :sswitch_1
    const-string v8, "style"

    .line 75
    .line 76
    invoke-virtual {v4, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v4

    .line 80
    if-nez v4, :cond_1

    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_1
    const/4 v4, 0x4

    .line 84
    goto :goto_2

    .line 85
    :sswitch_2
    const-string v8, "begin"

    .line 86
    .line 87
    invoke-virtual {v4, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v4

    .line 91
    if-nez v4, :cond_2

    .line 92
    .line 93
    goto :goto_1

    .line 94
    :cond_2
    const/4 v4, 0x3

    .line 95
    goto :goto_2

    .line 96
    :sswitch_3
    const-string v8, "end"

    .line 97
    .line 98
    invoke-virtual {v4, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v4

    .line 102
    if-nez v4, :cond_3

    .line 103
    .line 104
    goto :goto_1

    .line 105
    :cond_3
    const/4 v4, 0x2

    .line 106
    goto :goto_2

    .line 107
    :sswitch_4
    const-string v8, "dur"

    .line 108
    .line 109
    invoke-virtual {v4, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    move-result v4

    .line 113
    if-nez v4, :cond_4

    .line 114
    .line 115
    goto :goto_1

    .line 116
    :cond_4
    const/4 v4, 0x1

    .line 117
    goto :goto_2

    .line 118
    :sswitch_5
    const-string v8, "region"

    .line 119
    .line 120
    invoke-virtual {v4, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result v4

    .line 124
    if-nez v4, :cond_5

    .line 125
    .line 126
    goto :goto_1

    .line 127
    :cond_5
    const/4 v4, 0x0

    .line 128
    :goto_2
    packed-switch v4, :pswitch_data_0

    .line 129
    .line 130
    .line 131
    goto :goto_3

    .line 132
    :pswitch_0
    const-string v4, "#"

    .line 133
    .line 134
    invoke-virtual {v5, v4}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 135
    .line 136
    .line 137
    move-result v4

    .line 138
    if-eqz v4, :cond_6

    .line 139
    .line 140
    const/4 v4, 0x1

    .line 141
    invoke-virtual {v5, v4}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v4

    .line 145
    move-object v10, v4

    .line 146
    :cond_6
    :goto_3
    move-object/from16 v4, p2

    .line 147
    .line 148
    goto :goto_5

    .line 149
    :pswitch_1
    invoke-virtual {v5}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v4

    .line 153
    invoke-virtual {v4}, Ljava/lang/String;->isEmpty()Z

    .line 154
    .line 155
    .line 156
    move-result v5

    .line 157
    const/4 v8, 0x0

    .line 158
    if-eqz v5, :cond_7

    .line 159
    .line 160
    new-array v4, v8, [Ljava/lang/String;

    .line 161
    .line 162
    goto :goto_4

    .line 163
    :cond_7
    sget-object v5, Lw7/w;->a:Ljava/lang/String;

    .line 164
    .line 165
    const-string v5, "\\s+"

    .line 166
    .line 167
    const/4 v8, -0x1

    .line 168
    invoke-virtual {v4, v5, v8}, Ljava/lang/String;->split(Ljava/lang/String;I)[Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v4

    .line 172
    :goto_4
    array-length v5, v4

    .line 173
    if-lez v5, :cond_6

    .line 174
    .line 175
    move-object v3, v4

    .line 176
    goto :goto_3

    .line 177
    :pswitch_2
    invoke-static {v5, v1}, Lr9/e;->k(Ljava/lang/String;Lr9/d;)J

    .line 178
    .line 179
    .line 180
    move-result-wide v12

    .line 181
    goto :goto_3

    .line 182
    :pswitch_3
    invoke-static {v5, v1}, Lr9/e;->k(Ljava/lang/String;Lr9/d;)J

    .line 183
    .line 184
    .line 185
    move-result-wide v14

    .line 186
    goto :goto_3

    .line 187
    :pswitch_4
    invoke-static {v5, v1}, Lr9/e;->k(Ljava/lang/String;Lr9/d;)J

    .line 188
    .line 189
    .line 190
    move-result-wide v16

    .line 191
    goto :goto_3

    .line 192
    :pswitch_5
    move-object/from16 v4, p2

    .line 193
    .line 194
    invoke-virtual {v4, v5}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    move-result v8

    .line 198
    if-eqz v8, :cond_8

    .line 199
    .line 200
    move-object v9, v5

    .line 201
    :cond_8
    :goto_5
    add-int/lit8 v6, v6, 0x1

    .line 202
    .line 203
    goto/16 :goto_0

    .line 204
    .line 205
    :cond_9
    const-wide v18, -0x7fffffffffffffffL    # -4.9E-324

    .line 206
    .line 207
    .line 208
    .line 209
    .line 210
    if-eqz v11, :cond_b

    .line 211
    .line 212
    iget-wide v1, v11, Lr9/c;->d:J

    .line 213
    .line 214
    cmp-long v4, v1, v18

    .line 215
    .line 216
    if-eqz v4, :cond_b

    .line 217
    .line 218
    cmp-long v4, v12, v18

    .line 219
    .line 220
    if-eqz v4, :cond_a

    .line 221
    .line 222
    add-long/2addr v12, v1

    .line 223
    :cond_a
    cmp-long v4, v14, v18

    .line 224
    .line 225
    if-eqz v4, :cond_b

    .line 226
    .line 227
    add-long/2addr v14, v1

    .line 228
    :cond_b
    cmp-long v1, v14, v18

    .line 229
    .line 230
    if-nez v1, :cond_c

    .line 231
    .line 232
    cmp-long v1, v16, v18

    .line 233
    .line 234
    if-eqz v1, :cond_d

    .line 235
    .line 236
    add-long v14, v12, v16

    .line 237
    .line 238
    :cond_c
    move-wide v5, v14

    .line 239
    goto :goto_6

    .line 240
    :cond_d
    if-eqz v11, :cond_c

    .line 241
    .line 242
    iget-wide v1, v11, Lr9/c;->e:J

    .line 243
    .line 244
    cmp-long v4, v1, v18

    .line 245
    .line 246
    if-eqz v4, :cond_c

    .line 247
    .line 248
    move-wide v5, v1

    .line 249
    :goto_6
    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 250
    .line 251
    .line 252
    move-result-object v1

    .line 253
    new-instance v0, Lr9/c;

    .line 254
    .line 255
    const/4 v2, 0x0

    .line 256
    move-object v8, v3

    .line 257
    move-wide v3, v12

    .line 258
    invoke-direct/range {v0 .. v11}, Lr9/c;-><init>(Ljava/lang/String;Ljava/lang/String;JJLr9/g;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lr9/c;)V

    .line 259
    .line 260
    .line 261
    return-object v0

    .line 262
    nop

    .line 263
    :sswitch_data_0
    .sparse-switch
        -0x37b7d90c -> :sswitch_5
        0x18601 -> :sswitch_4
        0x188db -> :sswitch_3
        0x59478a9 -> :sswitch_2
        0x68b1db1 -> :sswitch_1
        0x4d0b70cd -> :sswitch_0
    .end sparse-switch

    .line 264
    .line 265
    .line 266
    .line 267
    .line 268
    .line 269
    .line 270
    .line 271
    .line 272
    .line 273
    .line 274
    .line 275
    .line 276
    .line 277
    .line 278
    .line 279
    .line 280
    .line 281
    .line 282
    .line 283
    .line 284
    .line 285
    .line 286
    .line 287
    .line 288
    .line 289
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static j(Lorg/xmlpull/v1/XmlPullParser;Lr9/g;)Lr9/g;
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    invoke-interface {v1}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeCount()I

    .line 4
    .line 5
    .line 6
    move-result v2

    .line 7
    const/4 v3, 0x0

    .line 8
    move-object/from16 v0, p1

    .line 9
    .line 10
    move v4, v3

    .line 11
    :goto_0
    if-ge v4, v2, :cond_42

    .line 12
    .line 13
    invoke-interface {v1, v4}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(I)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v5

    .line 17
    invoke-interface {v1, v4}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeName(I)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v6

    .line 21
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v6}, Ljava/lang/String;->hashCode()I

    .line 25
    .line 26
    .line 27
    move-result v7

    .line 28
    sparse-switch v7, :sswitch_data_0

    .line 29
    .line 30
    .line 31
    :goto_1
    const/4 v6, -0x1

    .line 32
    goto/16 :goto_2

    .line 33
    .line 34
    :sswitch_0
    const-string v7, "multiRowAlign"

    .line 35
    .line 36
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v6

    .line 40
    if-nez v6, :cond_0

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_0
    const/16 v6, 0x10

    .line 44
    .line 45
    goto/16 :goto_2

    .line 46
    .line 47
    :sswitch_1
    const-string v7, "backgroundColor"

    .line 48
    .line 49
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v6

    .line 53
    if-nez v6, :cond_1

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_1
    const/16 v6, 0xf

    .line 57
    .line 58
    goto/16 :goto_2

    .line 59
    .line 60
    :sswitch_2
    const-string v7, "rubyPosition"

    .line 61
    .line 62
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v6

    .line 66
    if-nez v6, :cond_2

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_2
    const/16 v6, 0xe

    .line 70
    .line 71
    goto/16 :goto_2

    .line 72
    .line 73
    :sswitch_3
    const-string v7, "textEmphasis"

    .line 74
    .line 75
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v6

    .line 79
    if-nez v6, :cond_3

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_3
    const/16 v6, 0xd

    .line 83
    .line 84
    goto/16 :goto_2

    .line 85
    .line 86
    :sswitch_4
    const-string v7, "fontSize"

    .line 87
    .line 88
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v6

    .line 92
    if-nez v6, :cond_4

    .line 93
    .line 94
    goto :goto_1

    .line 95
    :cond_4
    const/16 v6, 0xc

    .line 96
    .line 97
    goto/16 :goto_2

    .line 98
    .line 99
    :sswitch_5
    const-string v7, "textCombine"

    .line 100
    .line 101
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v6

    .line 105
    if-nez v6, :cond_5

    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_5
    const/16 v6, 0xb

    .line 109
    .line 110
    goto/16 :goto_2

    .line 111
    .line 112
    :sswitch_6
    const-string v7, "shear"

    .line 113
    .line 114
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result v6

    .line 118
    if-nez v6, :cond_6

    .line 119
    .line 120
    goto :goto_1

    .line 121
    :cond_6
    const/16 v6, 0xa

    .line 122
    .line 123
    goto/16 :goto_2

    .line 124
    .line 125
    :sswitch_7
    const-string v7, "color"

    .line 126
    .line 127
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v6

    .line 131
    if-nez v6, :cond_7

    .line 132
    .line 133
    goto :goto_1

    .line 134
    :cond_7
    const/16 v6, 0x9

    .line 135
    .line 136
    goto/16 :goto_2

    .line 137
    .line 138
    :sswitch_8
    const-string v7, "ruby"

    .line 139
    .line 140
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    move-result v6

    .line 144
    if-nez v6, :cond_8

    .line 145
    .line 146
    goto :goto_1

    .line 147
    :cond_8
    const/16 v6, 0x8

    .line 148
    .line 149
    goto/16 :goto_2

    .line 150
    .line 151
    :sswitch_9
    const-string v7, "id"

    .line 152
    .line 153
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 154
    .line 155
    .line 156
    move-result v6

    .line 157
    if-nez v6, :cond_9

    .line 158
    .line 159
    goto/16 :goto_1

    .line 160
    .line 161
    :cond_9
    const/4 v6, 0x7

    .line 162
    goto :goto_2

    .line 163
    :sswitch_a
    const-string v7, "fontWeight"

    .line 164
    .line 165
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result v6

    .line 169
    if-nez v6, :cond_a

    .line 170
    .line 171
    goto/16 :goto_1

    .line 172
    .line 173
    :cond_a
    const/4 v6, 0x6

    .line 174
    goto :goto_2

    .line 175
    :sswitch_b
    const-string v7, "textDecoration"

    .line 176
    .line 177
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result v6

    .line 181
    if-nez v6, :cond_b

    .line 182
    .line 183
    goto/16 :goto_1

    .line 184
    .line 185
    :cond_b
    const/4 v6, 0x5

    .line 186
    goto :goto_2

    .line 187
    :sswitch_c
    const-string v7, "origin"

    .line 188
    .line 189
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    move-result v6

    .line 193
    if-nez v6, :cond_c

    .line 194
    .line 195
    goto/16 :goto_1

    .line 196
    .line 197
    :cond_c
    const/4 v6, 0x4

    .line 198
    goto :goto_2

    .line 199
    :sswitch_d
    const-string v7, "textAlign"

    .line 200
    .line 201
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 202
    .line 203
    .line 204
    move-result v6

    .line 205
    if-nez v6, :cond_d

    .line 206
    .line 207
    goto/16 :goto_1

    .line 208
    .line 209
    :cond_d
    const/4 v6, 0x3

    .line 210
    goto :goto_2

    .line 211
    :sswitch_e
    const-string v7, "fontFamily"

    .line 212
    .line 213
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 214
    .line 215
    .line 216
    move-result v6

    .line 217
    if-nez v6, :cond_e

    .line 218
    .line 219
    goto/16 :goto_1

    .line 220
    .line 221
    :cond_e
    const/4 v6, 0x2

    .line 222
    goto :goto_2

    .line 223
    :sswitch_f
    const-string v7, "extent"

    .line 224
    .line 225
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 226
    .line 227
    .line 228
    move-result v6

    .line 229
    if-nez v6, :cond_f

    .line 230
    .line 231
    goto/16 :goto_1

    .line 232
    .line 233
    :cond_f
    const/4 v6, 0x1

    .line 234
    goto :goto_2

    .line 235
    :sswitch_10
    const-string v7, "fontStyle"

    .line 236
    .line 237
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 238
    .line 239
    .line 240
    move-result v6

    .line 241
    if-nez v6, :cond_10

    .line 242
    .line 243
    goto/16 :goto_1

    .line 244
    .line 245
    :cond_10
    move v6, v3

    .line 246
    :goto_2
    const-string v7, "none"

    .line 247
    .line 248
    const-string v14, "after"

    .line 249
    .line 250
    const-string v15, "before"

    .line 251
    .line 252
    const-string v8, "start"

    .line 253
    .line 254
    const-string v9, "right"

    .line 255
    .line 256
    const-string v11, "left"

    .line 257
    .line 258
    const-string v10, "end"

    .line 259
    .line 260
    const-string v12, "center"

    .line 261
    .line 262
    const/16 v17, 0x0

    .line 263
    .line 264
    const-string v13, "TtmlParser"

    .line 265
    .line 266
    packed-switch v6, :pswitch_data_0

    .line 267
    .line 268
    .line 269
    goto/16 :goto_1e

    .line 270
    .line 271
    :pswitch_0
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 272
    .line 273
    .line 274
    move-result-object v0

    .line 275
    invoke-static {v5}, Lkp/g9;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 276
    .line 277
    .line 278
    move-result-object v5

    .line 279
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 280
    .line 281
    .line 282
    invoke-virtual {v5}, Ljava/lang/String;->hashCode()I

    .line 283
    .line 284
    .line 285
    move-result v6

    .line 286
    sparse-switch v6, :sswitch_data_1

    .line 287
    .line 288
    .line 289
    :goto_3
    const/4 v9, -0x1

    .line 290
    goto :goto_4

    .line 291
    :sswitch_11
    invoke-virtual {v5, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 292
    .line 293
    .line 294
    move-result v5

    .line 295
    if-nez v5, :cond_11

    .line 296
    .line 297
    goto :goto_3

    .line 298
    :cond_11
    const/4 v9, 0x4

    .line 299
    goto :goto_4

    .line 300
    :sswitch_12
    invoke-virtual {v5, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 301
    .line 302
    .line 303
    move-result v5

    .line 304
    if-nez v5, :cond_12

    .line 305
    .line 306
    goto :goto_3

    .line 307
    :cond_12
    const/4 v9, 0x3

    .line 308
    goto :goto_4

    .line 309
    :sswitch_13
    invoke-virtual {v5, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 310
    .line 311
    .line 312
    move-result v5

    .line 313
    if-nez v5, :cond_13

    .line 314
    .line 315
    goto :goto_3

    .line 316
    :cond_13
    const/4 v9, 0x2

    .line 317
    goto :goto_4

    .line 318
    :sswitch_14
    invoke-virtual {v5, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 319
    .line 320
    .line 321
    move-result v5

    .line 322
    if-nez v5, :cond_14

    .line 323
    .line 324
    goto :goto_3

    .line 325
    :cond_14
    const/4 v9, 0x1

    .line 326
    goto :goto_4

    .line 327
    :sswitch_15
    invoke-virtual {v5, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 328
    .line 329
    .line 330
    move-result v5

    .line 331
    if-nez v5, :cond_15

    .line 332
    .line 333
    goto :goto_3

    .line 334
    :cond_15
    move v9, v3

    .line 335
    :goto_4
    packed-switch v9, :pswitch_data_1

    .line 336
    .line 337
    .line 338
    :goto_5
    move-object/from16 v5, v17

    .line 339
    .line 340
    goto :goto_6

    .line 341
    :pswitch_1
    sget-object v17, Landroid/text/Layout$Alignment;->ALIGN_NORMAL:Landroid/text/Layout$Alignment;

    .line 342
    .line 343
    goto :goto_5

    .line 344
    :pswitch_2
    sget-object v17, Landroid/text/Layout$Alignment;->ALIGN_OPPOSITE:Landroid/text/Layout$Alignment;

    .line 345
    .line 346
    goto :goto_5

    .line 347
    :pswitch_3
    sget-object v17, Landroid/text/Layout$Alignment;->ALIGN_CENTER:Landroid/text/Layout$Alignment;

    .line 348
    .line 349
    goto :goto_5

    .line 350
    :goto_6
    iput-object v5, v0, Lr9/g;->p:Landroid/text/Layout$Alignment;

    .line 351
    .line 352
    goto/16 :goto_1e

    .line 353
    .line 354
    :pswitch_4
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 355
    .line 356
    .line 357
    move-result-object v0

    .line 358
    :try_start_0
    invoke-static {v5, v3}, Lw7/d;->a(Ljava/lang/String;Z)I

    .line 359
    .line 360
    .line 361
    move-result v6

    .line 362
    iput v6, v0, Lr9/g;->d:I

    .line 363
    .line 364
    const/4 v6, 0x1

    .line 365
    iput-boolean v6, v0, Lr9/g;->e:Z
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 366
    .line 367
    goto/16 :goto_1e

    .line 368
    .line 369
    :catch_0
    const-string v6, "Failed parsing background value: "

    .line 370
    .line 371
    invoke-static {v6, v5, v13}, Lvj/b;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 372
    .line 373
    .line 374
    goto/16 :goto_1e

    .line 375
    .line 376
    :pswitch_5
    invoke-static {v5}, Lkp/g9;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 377
    .line 378
    .line 379
    move-result-object v5

    .line 380
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 381
    .line 382
    .line 383
    invoke-virtual {v5, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 384
    .line 385
    .line 386
    move-result v6

    .line 387
    if-nez v6, :cond_17

    .line 388
    .line 389
    invoke-virtual {v5, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 390
    .line 391
    .line 392
    move-result v5

    .line 393
    if-nez v5, :cond_16

    .line 394
    .line 395
    goto/16 :goto_1e

    .line 396
    .line 397
    :cond_16
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 398
    .line 399
    .line 400
    move-result-object v0

    .line 401
    const/4 v5, 0x2

    .line 402
    iput v5, v0, Lr9/g;->n:I

    .line 403
    .line 404
    goto/16 :goto_1e

    .line 405
    .line 406
    :cond_17
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 407
    .line 408
    .line 409
    move-result-object v0

    .line 410
    const/4 v6, 0x1

    .line 411
    iput v6, v0, Lr9/g;->n:I

    .line 412
    .line 413
    goto/16 :goto_1e

    .line 414
    .line 415
    :pswitch_6
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 416
    .line 417
    .line 418
    move-result-object v0

    .line 419
    sget-object v6, Lr9/b;->d:Ljava/util/regex/Pattern;

    .line 420
    .line 421
    if-nez v5, :cond_18

    .line 422
    .line 423
    :goto_7
    move-object/from16 v5, v17

    .line 424
    .line 425
    goto/16 :goto_14

    .line 426
    .line 427
    :cond_18
    invoke-virtual {v5}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 428
    .line 429
    .line 430
    move-result-object v5

    .line 431
    invoke-static {v5}, Lkp/g9;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 432
    .line 433
    .line 434
    move-result-object v5

    .line 435
    invoke-virtual {v5}, Ljava/lang/String;->isEmpty()Z

    .line 436
    .line 437
    .line 438
    move-result v6

    .line 439
    if-eqz v6, :cond_19

    .line 440
    .line 441
    goto :goto_7

    .line 442
    :cond_19
    sget-object v6, Lr9/b;->d:Ljava/util/regex/Pattern;

    .line 443
    .line 444
    invoke-static {v5, v6}, Landroid/text/TextUtils;->split(Ljava/lang/String;Ljava/util/regex/Pattern;)[Ljava/lang/String;

    .line 445
    .line 446
    .line 447
    move-result-object v5

    .line 448
    array-length v6, v5

    .line 449
    if-eqz v6, :cond_1b

    .line 450
    .line 451
    const/4 v8, 0x1

    .line 452
    if-eq v6, v8, :cond_1a

    .line 453
    .line 454
    array-length v6, v5

    .line 455
    invoke-virtual {v5}, [Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 456
    .line 457
    .line 458
    move-result-object v5

    .line 459
    check-cast v5, [Ljava/lang/Object;

    .line 460
    .line 461
    invoke-static {v6, v5}, Lhr/k0;->o(I[Ljava/lang/Object;)Lhr/k0;

    .line 462
    .line 463
    .line 464
    move-result-object v5

    .line 465
    goto :goto_8

    .line 466
    :cond_1a
    aget-object v5, v5, v3

    .line 467
    .line 468
    new-instance v6, Lhr/j1;

    .line 469
    .line 470
    invoke-direct {v6, v5}, Lhr/j1;-><init>(Ljava/lang/Object;)V

    .line 471
    .line 472
    .line 473
    move-object v5, v6

    .line 474
    goto :goto_8

    .line 475
    :cond_1b
    sget-object v5, Lhr/d1;->m:Lhr/d1;

    .line 476
    .line 477
    :goto_8
    sget-object v6, Lr9/b;->h:Lhr/k0;

    .line 478
    .line 479
    invoke-static {v6, v5}, Lhr/q;->j(Ljava/util/Set;Lhr/k0;)Lhr/f1;

    .line 480
    .line 481
    .line 482
    move-result-object v6

    .line 483
    invoke-virtual {v6}, Lhr/f1;->c()Lhr/l1;

    .line 484
    .line 485
    .line 486
    move-result-object v6

    .line 487
    check-cast v6, Lhr/l0;

    .line 488
    .line 489
    invoke-virtual {v6}, Lhr/l0;->hasNext()Z

    .line 490
    .line 491
    .line 492
    move-result v8

    .line 493
    const-string v9, "outside"

    .line 494
    .line 495
    if-eqz v8, :cond_1c

    .line 496
    .line 497
    invoke-virtual {v6}, Lhr/l0;->next()Ljava/lang/Object;

    .line 498
    .line 499
    .line 500
    move-result-object v6

    .line 501
    goto :goto_9

    .line 502
    :cond_1c
    move-object v6, v9

    .line 503
    :goto_9
    check-cast v6, Ljava/lang/String;

    .line 504
    .line 505
    invoke-virtual {v6}, Ljava/lang/String;->hashCode()I

    .line 506
    .line 507
    .line 508
    move-result v8

    .line 509
    const v10, -0x5305c081

    .line 510
    .line 511
    .line 512
    if-eq v8, v10, :cond_1f

    .line 513
    .line 514
    const v10, -0x41ecca5b

    .line 515
    .line 516
    .line 517
    if-eq v8, v10, :cond_1e

    .line 518
    .line 519
    const v9, 0x58705dc

    .line 520
    .line 521
    .line 522
    if-eq v8, v9, :cond_1d

    .line 523
    .line 524
    goto :goto_a

    .line 525
    :cond_1d
    invoke-virtual {v6, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 526
    .line 527
    .line 528
    move-result v6

    .line 529
    if-eqz v6, :cond_20

    .line 530
    .line 531
    const/4 v6, 0x2

    .line 532
    goto :goto_b

    .line 533
    :cond_1e
    invoke-virtual {v6, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 534
    .line 535
    .line 536
    move-result v6

    .line 537
    if-eqz v6, :cond_20

    .line 538
    .line 539
    const/4 v6, -0x2

    .line 540
    goto :goto_b

    .line 541
    :cond_1f
    invoke-virtual {v6, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 542
    .line 543
    .line 544
    move-result v6

    .line 545
    :cond_20
    :goto_a
    const/4 v6, 0x1

    .line 546
    :goto_b
    sget-object v8, Lr9/b;->e:Lhr/k0;

    .line 547
    .line 548
    invoke-static {v8, v5}, Lhr/q;->j(Ljava/util/Set;Lhr/k0;)Lhr/f1;

    .line 549
    .line 550
    .line 551
    move-result-object v8

    .line 552
    invoke-virtual {v8}, Lhr/f1;->isEmpty()Z

    .line 553
    .line 554
    .line 555
    move-result v9

    .line 556
    if-nez v9, :cond_24

    .line 557
    .line 558
    new-instance v5, Lhr/l0;

    .line 559
    .line 560
    iget-object v9, v8, Lhr/f1;->d:Ljava/util/Set;

    .line 561
    .line 562
    iget-object v8, v8, Lhr/f1;->e:Ljava/util/Set;

    .line 563
    .line 564
    invoke-direct {v5, v9, v8}, Lhr/l0;-><init>(Ljava/util/Set;Ljava/util/Set;)V

    .line 565
    .line 566
    .line 567
    invoke-virtual {v5}, Lhr/l0;->next()Ljava/lang/Object;

    .line 568
    .line 569
    .line 570
    move-result-object v5

    .line 571
    check-cast v5, Ljava/lang/String;

    .line 572
    .line 573
    invoke-virtual {v5}, Ljava/lang/String;->hashCode()I

    .line 574
    .line 575
    .line 576
    move-result v8

    .line 577
    const v9, 0x2dddaf

    .line 578
    .line 579
    .line 580
    if-eq v8, v9, :cond_22

    .line 581
    .line 582
    const v9, 0x33af38

    .line 583
    .line 584
    .line 585
    if-eq v8, v9, :cond_21

    .line 586
    .line 587
    goto :goto_c

    .line 588
    :cond_21
    invoke-virtual {v5, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 589
    .line 590
    .line 591
    move-result v5

    .line 592
    if-eqz v5, :cond_23

    .line 593
    .line 594
    move v10, v3

    .line 595
    goto :goto_d

    .line 596
    :cond_22
    const-string v7, "auto"

    .line 597
    .line 598
    invoke-virtual {v5, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 599
    .line 600
    .line 601
    move-result v5

    .line 602
    :cond_23
    :goto_c
    const/4 v10, -0x1

    .line 603
    :goto_d
    new-instance v5, Lr9/b;

    .line 604
    .line 605
    invoke-direct {v5, v10, v3, v6}, Lr9/b;-><init>(III)V

    .line 606
    .line 607
    .line 608
    goto/16 :goto_14

    .line 609
    .line 610
    :cond_24
    sget-object v7, Lr9/b;->g:Lhr/k0;

    .line 611
    .line 612
    invoke-static {v7, v5}, Lhr/q;->j(Ljava/util/Set;Lhr/k0;)Lhr/f1;

    .line 613
    .line 614
    .line 615
    move-result-object v7

    .line 616
    sget-object v8, Lr9/b;->f:Lhr/k0;

    .line 617
    .line 618
    invoke-static {v8, v5}, Lhr/q;->j(Ljava/util/Set;Lhr/k0;)Lhr/f1;

    .line 619
    .line 620
    .line 621
    move-result-object v5

    .line 622
    invoke-virtual {v7}, Lhr/f1;->isEmpty()Z

    .line 623
    .line 624
    .line 625
    move-result v8

    .line 626
    if-eqz v8, :cond_25

    .line 627
    .line 628
    invoke-virtual {v5}, Lhr/f1;->isEmpty()Z

    .line 629
    .line 630
    .line 631
    move-result v8

    .line 632
    if-eqz v8, :cond_25

    .line 633
    .line 634
    new-instance v5, Lr9/b;

    .line 635
    .line 636
    const/4 v7, -0x1

    .line 637
    invoke-direct {v5, v7, v3, v6}, Lr9/b;-><init>(III)V

    .line 638
    .line 639
    .line 640
    goto/16 :goto_14

    .line 641
    .line 642
    :cond_25
    invoke-virtual {v7}, Lhr/f1;->c()Lhr/l1;

    .line 643
    .line 644
    .line 645
    move-result-object v7

    .line 646
    check-cast v7, Lhr/l0;

    .line 647
    .line 648
    invoke-virtual {v7}, Lhr/l0;->hasNext()Z

    .line 649
    .line 650
    .line 651
    move-result v8

    .line 652
    const-string v9, "filled"

    .line 653
    .line 654
    if-eqz v8, :cond_26

    .line 655
    .line 656
    invoke-virtual {v7}, Lhr/l0;->next()Ljava/lang/Object;

    .line 657
    .line 658
    .line 659
    move-result-object v7

    .line 660
    goto :goto_e

    .line 661
    :cond_26
    move-object v7, v9

    .line 662
    :goto_e
    check-cast v7, Ljava/lang/String;

    .line 663
    .line 664
    invoke-virtual {v7}, Ljava/lang/String;->hashCode()I

    .line 665
    .line 666
    .line 667
    move-result v8

    .line 668
    const v10, -0x4bf7529e

    .line 669
    .line 670
    .line 671
    if-eq v8, v10, :cond_28

    .line 672
    .line 673
    const v9, 0x34264a

    .line 674
    .line 675
    .line 676
    if-eq v8, v9, :cond_27

    .line 677
    .line 678
    goto :goto_f

    .line 679
    :cond_27
    const-string v8, "open"

    .line 680
    .line 681
    invoke-virtual {v7, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 682
    .line 683
    .line 684
    move-result v7

    .line 685
    if-eqz v7, :cond_29

    .line 686
    .line 687
    const/4 v7, 0x2

    .line 688
    goto :goto_10

    .line 689
    :cond_28
    invoke-virtual {v7, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 690
    .line 691
    .line 692
    move-result v7

    .line 693
    :cond_29
    :goto_f
    const/4 v7, 0x1

    .line 694
    :goto_10
    invoke-virtual {v5}, Lhr/f1;->c()Lhr/l1;

    .line 695
    .line 696
    .line 697
    move-result-object v5

    .line 698
    check-cast v5, Lhr/l0;

    .line 699
    .line 700
    invoke-virtual {v5}, Lhr/l0;->hasNext()Z

    .line 701
    .line 702
    .line 703
    move-result v8

    .line 704
    const-string v9, "circle"

    .line 705
    .line 706
    if-eqz v8, :cond_2a

    .line 707
    .line 708
    invoke-virtual {v5}, Lhr/l0;->next()Ljava/lang/Object;

    .line 709
    .line 710
    .line 711
    move-result-object v5

    .line 712
    goto :goto_11

    .line 713
    :cond_2a
    move-object v5, v9

    .line 714
    :goto_11
    check-cast v5, Ljava/lang/String;

    .line 715
    .line 716
    invoke-virtual {v5}, Ljava/lang/String;->hashCode()I

    .line 717
    .line 718
    .line 719
    move-result v8

    .line 720
    const v10, -0x51134330

    .line 721
    .line 722
    .line 723
    if-eq v8, v10, :cond_2d

    .line 724
    .line 725
    const v9, -0x35fdaa48    # -2135406.0f

    .line 726
    .line 727
    .line 728
    if-eq v8, v9, :cond_2c

    .line 729
    .line 730
    const v9, 0x18549

    .line 731
    .line 732
    .line 733
    if-eq v8, v9, :cond_2b

    .line 734
    .line 735
    goto :goto_12

    .line 736
    :cond_2b
    const-string v8, "dot"

    .line 737
    .line 738
    invoke-virtual {v5, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 739
    .line 740
    .line 741
    move-result v5

    .line 742
    if-eqz v5, :cond_2e

    .line 743
    .line 744
    const/4 v11, 0x2

    .line 745
    goto :goto_13

    .line 746
    :cond_2c
    const-string v8, "sesame"

    .line 747
    .line 748
    invoke-virtual {v5, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 749
    .line 750
    .line 751
    move-result v5

    .line 752
    if-eqz v5, :cond_2e

    .line 753
    .line 754
    const/4 v11, 0x3

    .line 755
    goto :goto_13

    .line 756
    :cond_2d
    invoke-virtual {v5, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 757
    .line 758
    .line 759
    move-result v5

    .line 760
    :cond_2e
    :goto_12
    const/4 v11, 0x1

    .line 761
    :goto_13
    new-instance v5, Lr9/b;

    .line 762
    .line 763
    invoke-direct {v5, v11, v7, v6}, Lr9/b;-><init>(III)V

    .line 764
    .line 765
    .line 766
    :goto_14
    iput-object v5, v0, Lr9/g;->r:Lr9/b;

    .line 767
    .line 768
    goto/16 :goto_1e

    .line 769
    .line 770
    :pswitch_7
    :try_start_1
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 771
    .line 772
    .line 773
    move-result-object v0

    .line 774
    invoke-static {v5, v0}, Lr9/e;->e(Ljava/lang/String;Lr9/g;)V
    :try_end_1
    .catch Ll9/f; {:try_start_1 .. :try_end_1} :catch_1

    .line 775
    .line 776
    .line 777
    goto/16 :goto_1e

    .line 778
    .line 779
    :catch_1
    const-string v6, "Failed parsing fontSize value: "

    .line 780
    .line 781
    invoke-static {v6, v5, v13}, Lvj/b;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 782
    .line 783
    .line 784
    goto/16 :goto_1e

    .line 785
    .line 786
    :pswitch_8
    invoke-static {v5}, Lkp/g9;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 787
    .line 788
    .line 789
    move-result-object v5

    .line 790
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 791
    .line 792
    .line 793
    const-string v6, "all"

    .line 794
    .line 795
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 796
    .line 797
    .line 798
    move-result v6

    .line 799
    if-nez v6, :cond_30

    .line 800
    .line 801
    invoke-virtual {v5, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 802
    .line 803
    .line 804
    move-result v5

    .line 805
    if-nez v5, :cond_2f

    .line 806
    .line 807
    goto/16 :goto_1e

    .line 808
    .line 809
    :cond_2f
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 810
    .line 811
    .line 812
    move-result-object v0

    .line 813
    iput v3, v0, Lr9/g;->q:I

    .line 814
    .line 815
    goto/16 :goto_1e

    .line 816
    .line 817
    :cond_30
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 818
    .line 819
    .line 820
    move-result-object v0

    .line 821
    const/4 v6, 0x1

    .line 822
    iput v6, v0, Lr9/g;->q:I

    .line 823
    .line 824
    goto/16 :goto_1e

    .line 825
    .line 826
    :pswitch_9
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 827
    .line 828
    .line 829
    move-result-object v6

    .line 830
    sget-object v0, Lr9/e;->h:Ljava/util/regex/Pattern;

    .line 831
    .line 832
    invoke-virtual {v0, v5}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 833
    .line 834
    .line 835
    move-result-object v0

    .line 836
    invoke-virtual {v0}, Ljava/util/regex/Matcher;->matches()Z

    .line 837
    .line 838
    .line 839
    move-result v7

    .line 840
    const v8, 0x7f7fffff    # Float.MAX_VALUE

    .line 841
    .line 842
    .line 843
    if-nez v7, :cond_31

    .line 844
    .line 845
    const-string v0, "Invalid value for shear: "

    .line 846
    .line 847
    invoke-static {v0, v5, v13}, Lvj/b;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 848
    .line 849
    .line 850
    goto :goto_15

    .line 851
    :cond_31
    const/4 v7, 0x1

    .line 852
    :try_start_2
    invoke-virtual {v0, v7}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 853
    .line 854
    .line 855
    move-result-object v0

    .line 856
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 857
    .line 858
    .line 859
    invoke-static {v0}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 860
    .line 861
    .line 862
    move-result v0

    .line 863
    const/high16 v7, -0x3d380000    # -100.0f

    .line 864
    .line 865
    invoke-static {v7, v0}, Ljava/lang/Math;->max(FF)F

    .line 866
    .line 867
    .line 868
    move-result v0

    .line 869
    const/high16 v7, 0x42c80000    # 100.0f

    .line 870
    .line 871
    invoke-static {v7, v0}, Ljava/lang/Math;->min(FF)F

    .line 872
    .line 873
    .line 874
    move-result v8
    :try_end_2
    .catch Ljava/lang/NumberFormatException; {:try_start_2 .. :try_end_2} :catch_2

    .line 875
    goto :goto_15

    .line 876
    :catch_2
    move-exception v0

    .line 877
    new-instance v7, Ljava/lang/StringBuilder;

    .line 878
    .line 879
    const-string v9, "Failed to parse shear: "

    .line 880
    .line 881
    invoke-direct {v7, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 882
    .line 883
    .line 884
    invoke-virtual {v7, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 885
    .line 886
    .line 887
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 888
    .line 889
    .line 890
    move-result-object v5

    .line 891
    invoke-static {v13, v5, v0}, Lw7/a;->z(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 892
    .line 893
    .line 894
    :goto_15
    iput v8, v6, Lr9/g;->s:F

    .line 895
    .line 896
    move-object v0, v6

    .line 897
    goto/16 :goto_1e

    .line 898
    .line 899
    :pswitch_a
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 900
    .line 901
    .line 902
    move-result-object v0

    .line 903
    :try_start_3
    invoke-static {v5, v3}, Lw7/d;->a(Ljava/lang/String;Z)I

    .line 904
    .line 905
    .line 906
    move-result v6

    .line 907
    iput v6, v0, Lr9/g;->b:I

    .line 908
    .line 909
    const/4 v6, 0x1

    .line 910
    iput-boolean v6, v0, Lr9/g;->c:Z
    :try_end_3
    .catch Ljava/lang/IllegalArgumentException; {:try_start_3 .. :try_end_3} :catch_3

    .line 911
    .line 912
    goto/16 :goto_1e

    .line 913
    .line 914
    :catch_3
    const-string v6, "Failed parsing color value: "

    .line 915
    .line 916
    invoke-static {v6, v5, v13}, Lvj/b;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 917
    .line 918
    .line 919
    goto/16 :goto_1e

    .line 920
    .line 921
    :pswitch_b
    const/4 v7, -0x1

    .line 922
    invoke-static {v5}, Lkp/g9;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 923
    .line 924
    .line 925
    move-result-object v5

    .line 926
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 927
    .line 928
    .line 929
    invoke-virtual {v5}, Ljava/lang/String;->hashCode()I

    .line 930
    .line 931
    .line 932
    move-result v6

    .line 933
    sparse-switch v6, :sswitch_data_2

    .line 934
    .line 935
    .line 936
    :goto_16
    move v8, v7

    .line 937
    goto :goto_17

    .line 938
    :sswitch_16
    const-string v6, "text"

    .line 939
    .line 940
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 941
    .line 942
    .line 943
    move-result v5

    .line 944
    if-nez v5, :cond_32

    .line 945
    .line 946
    goto :goto_16

    .line 947
    :cond_32
    const/4 v8, 0x5

    .line 948
    goto :goto_17

    .line 949
    :sswitch_17
    const-string v6, "base"

    .line 950
    .line 951
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 952
    .line 953
    .line 954
    move-result v5

    .line 955
    if-nez v5, :cond_33

    .line 956
    .line 957
    goto :goto_16

    .line 958
    :cond_33
    const/4 v8, 0x4

    .line 959
    goto :goto_17

    .line 960
    :sswitch_18
    const-string v6, "textContainer"

    .line 961
    .line 962
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 963
    .line 964
    .line 965
    move-result v5

    .line 966
    if-nez v5, :cond_34

    .line 967
    .line 968
    goto :goto_16

    .line 969
    :cond_34
    const/4 v8, 0x3

    .line 970
    goto :goto_17

    .line 971
    :sswitch_19
    const-string v6, "delimiter"

    .line 972
    .line 973
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 974
    .line 975
    .line 976
    move-result v5

    .line 977
    if-nez v5, :cond_35

    .line 978
    .line 979
    goto :goto_16

    .line 980
    :cond_35
    const/4 v8, 0x2

    .line 981
    goto :goto_17

    .line 982
    :sswitch_1a
    const-string v6, "container"

    .line 983
    .line 984
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 985
    .line 986
    .line 987
    move-result v5

    .line 988
    if-nez v5, :cond_36

    .line 989
    .line 990
    goto :goto_16

    .line 991
    :cond_36
    const/4 v8, 0x1

    .line 992
    goto :goto_17

    .line 993
    :sswitch_1b
    const-string v6, "baseContainer"

    .line 994
    .line 995
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 996
    .line 997
    .line 998
    move-result v5

    .line 999
    if-nez v5, :cond_37

    .line 1000
    .line 1001
    goto :goto_16

    .line 1002
    :cond_37
    move v8, v3

    .line 1003
    :goto_17
    packed-switch v8, :pswitch_data_2

    .line 1004
    .line 1005
    .line 1006
    goto/16 :goto_1e

    .line 1007
    .line 1008
    :pswitch_c
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 1009
    .line 1010
    .line 1011
    move-result-object v0

    .line 1012
    const/4 v6, 0x3

    .line 1013
    iput v6, v0, Lr9/g;->m:I

    .line 1014
    .line 1015
    goto/16 :goto_1e

    .line 1016
    .line 1017
    :pswitch_d
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 1018
    .line 1019
    .line 1020
    move-result-object v0

    .line 1021
    const/4 v13, 0x4

    .line 1022
    iput v13, v0, Lr9/g;->m:I

    .line 1023
    .line 1024
    goto/16 :goto_1e

    .line 1025
    .line 1026
    :pswitch_e
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 1027
    .line 1028
    .line 1029
    move-result-object v0

    .line 1030
    const/4 v6, 0x1

    .line 1031
    iput v6, v0, Lr9/g;->m:I

    .line 1032
    .line 1033
    goto/16 :goto_1e

    .line 1034
    .line 1035
    :pswitch_f
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 1036
    .line 1037
    .line 1038
    move-result-object v0

    .line 1039
    const/4 v14, 0x2

    .line 1040
    iput v14, v0, Lr9/g;->m:I

    .line 1041
    .line 1042
    goto/16 :goto_1e

    .line 1043
    .line 1044
    :pswitch_10
    const-string v6, "style"

    .line 1045
    .line 1046
    invoke-interface {v1}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 1047
    .line 1048
    .line 1049
    move-result-object v7

    .line 1050
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1051
    .line 1052
    .line 1053
    move-result v6

    .line 1054
    if-eqz v6, :cond_41

    .line 1055
    .line 1056
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 1057
    .line 1058
    .line 1059
    move-result-object v0

    .line 1060
    iput-object v5, v0, Lr9/g;->l:Ljava/lang/String;

    .line 1061
    .line 1062
    goto/16 :goto_1e

    .line 1063
    .line 1064
    :pswitch_11
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 1065
    .line 1066
    .line 1067
    move-result-object v0

    .line 1068
    const-string v6, "bold"

    .line 1069
    .line 1070
    invoke-virtual {v6, v5}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1071
    .line 1072
    .line 1073
    move-result v5

    .line 1074
    iput v5, v0, Lr9/g;->h:I

    .line 1075
    .line 1076
    goto/16 :goto_1e

    .line 1077
    .line 1078
    :pswitch_12
    const/4 v6, 0x3

    .line 1079
    const/4 v7, -0x1

    .line 1080
    const/4 v14, 0x2

    .line 1081
    invoke-static {v5}, Lkp/g9;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 1082
    .line 1083
    .line 1084
    move-result-object v5

    .line 1085
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1086
    .line 1087
    .line 1088
    invoke-virtual {v5}, Ljava/lang/String;->hashCode()I

    .line 1089
    .line 1090
    .line 1091
    move-result v8

    .line 1092
    sparse-switch v8, :sswitch_data_3

    .line 1093
    .line 1094
    .line 1095
    :goto_18
    move v10, v7

    .line 1096
    goto :goto_19

    .line 1097
    :sswitch_1c
    const-string v8, "linethrough"

    .line 1098
    .line 1099
    invoke-virtual {v5, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1100
    .line 1101
    .line 1102
    move-result v5

    .line 1103
    if-nez v5, :cond_38

    .line 1104
    .line 1105
    goto :goto_18

    .line 1106
    :cond_38
    move v10, v6

    .line 1107
    goto :goto_19

    .line 1108
    :sswitch_1d
    const-string v6, "nolinethrough"

    .line 1109
    .line 1110
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1111
    .line 1112
    .line 1113
    move-result v5

    .line 1114
    if-nez v5, :cond_39

    .line 1115
    .line 1116
    goto :goto_18

    .line 1117
    :cond_39
    move v10, v14

    .line 1118
    goto :goto_19

    .line 1119
    :sswitch_1e
    const-string v6, "underline"

    .line 1120
    .line 1121
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1122
    .line 1123
    .line 1124
    move-result v5

    .line 1125
    if-nez v5, :cond_3a

    .line 1126
    .line 1127
    goto :goto_18

    .line 1128
    :cond_3a
    const/4 v10, 0x1

    .line 1129
    goto :goto_19

    .line 1130
    :sswitch_1f
    const-string v6, "nounderline"

    .line 1131
    .line 1132
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1133
    .line 1134
    .line 1135
    move-result v5

    .line 1136
    if-nez v5, :cond_3b

    .line 1137
    .line 1138
    goto :goto_18

    .line 1139
    :cond_3b
    move v10, v3

    .line 1140
    :goto_19
    packed-switch v10, :pswitch_data_3

    .line 1141
    .line 1142
    .line 1143
    goto/16 :goto_1e

    .line 1144
    .line 1145
    :pswitch_13
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 1146
    .line 1147
    .line 1148
    move-result-object v0

    .line 1149
    const/4 v15, 0x1

    .line 1150
    iput v15, v0, Lr9/g;->f:I

    .line 1151
    .line 1152
    goto/16 :goto_1e

    .line 1153
    .line 1154
    :pswitch_14
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 1155
    .line 1156
    .line 1157
    move-result-object v0

    .line 1158
    iput v3, v0, Lr9/g;->f:I

    .line 1159
    .line 1160
    goto/16 :goto_1e

    .line 1161
    .line 1162
    :pswitch_15
    const/4 v15, 0x1

    .line 1163
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 1164
    .line 1165
    .line 1166
    move-result-object v0

    .line 1167
    iput v15, v0, Lr9/g;->g:I

    .line 1168
    .line 1169
    goto/16 :goto_1e

    .line 1170
    .line 1171
    :pswitch_16
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 1172
    .line 1173
    .line 1174
    move-result-object v0

    .line 1175
    iput v3, v0, Lr9/g;->g:I

    .line 1176
    .line 1177
    goto/16 :goto_1e

    .line 1178
    .line 1179
    :pswitch_17
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 1180
    .line 1181
    .line 1182
    move-result-object v0

    .line 1183
    iput-object v5, v0, Lr9/g;->t:Ljava/lang/String;

    .line 1184
    .line 1185
    goto/16 :goto_1e

    .line 1186
    .line 1187
    :pswitch_18
    const/4 v6, 0x3

    .line 1188
    const/4 v7, -0x1

    .line 1189
    const/4 v13, 0x4

    .line 1190
    const/4 v14, 0x2

    .line 1191
    const/4 v15, 0x1

    .line 1192
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 1193
    .line 1194
    .line 1195
    move-result-object v0

    .line 1196
    invoke-static {v5}, Lkp/g9;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 1197
    .line 1198
    .line 1199
    move-result-object v5

    .line 1200
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1201
    .line 1202
    .line 1203
    invoke-virtual {v5}, Ljava/lang/String;->hashCode()I

    .line 1204
    .line 1205
    .line 1206
    move-result v16

    .line 1207
    sparse-switch v16, :sswitch_data_4

    .line 1208
    .line 1209
    .line 1210
    :goto_1a
    move v9, v7

    .line 1211
    goto :goto_1b

    .line 1212
    :sswitch_20
    invoke-virtual {v5, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1213
    .line 1214
    .line 1215
    move-result v5

    .line 1216
    if-nez v5, :cond_3c

    .line 1217
    .line 1218
    goto :goto_1a

    .line 1219
    :cond_3c
    move v9, v13

    .line 1220
    goto :goto_1b

    .line 1221
    :sswitch_21
    invoke-virtual {v5, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1222
    .line 1223
    .line 1224
    move-result v5

    .line 1225
    if-nez v5, :cond_3d

    .line 1226
    .line 1227
    goto :goto_1a

    .line 1228
    :cond_3d
    move v9, v6

    .line 1229
    goto :goto_1b

    .line 1230
    :sswitch_22
    invoke-virtual {v5, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1231
    .line 1232
    .line 1233
    move-result v5

    .line 1234
    if-nez v5, :cond_3e

    .line 1235
    .line 1236
    goto :goto_1a

    .line 1237
    :cond_3e
    move v9, v14

    .line 1238
    goto :goto_1b

    .line 1239
    :sswitch_23
    invoke-virtual {v5, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1240
    .line 1241
    .line 1242
    move-result v5

    .line 1243
    if-nez v5, :cond_3f

    .line 1244
    .line 1245
    goto :goto_1a

    .line 1246
    :cond_3f
    move v9, v15

    .line 1247
    goto :goto_1b

    .line 1248
    :sswitch_24
    invoke-virtual {v5, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1249
    .line 1250
    .line 1251
    move-result v5

    .line 1252
    if-nez v5, :cond_40

    .line 1253
    .line 1254
    goto :goto_1a

    .line 1255
    :cond_40
    move v9, v3

    .line 1256
    :goto_1b
    packed-switch v9, :pswitch_data_4

    .line 1257
    .line 1258
    .line 1259
    :goto_1c
    move-object/from16 v5, v17

    .line 1260
    .line 1261
    goto :goto_1d

    .line 1262
    :pswitch_19
    sget-object v17, Landroid/text/Layout$Alignment;->ALIGN_NORMAL:Landroid/text/Layout$Alignment;

    .line 1263
    .line 1264
    goto :goto_1c

    .line 1265
    :pswitch_1a
    sget-object v17, Landroid/text/Layout$Alignment;->ALIGN_OPPOSITE:Landroid/text/Layout$Alignment;

    .line 1266
    .line 1267
    goto :goto_1c

    .line 1268
    :pswitch_1b
    sget-object v17, Landroid/text/Layout$Alignment;->ALIGN_CENTER:Landroid/text/Layout$Alignment;

    .line 1269
    .line 1270
    goto :goto_1c

    .line 1271
    :goto_1d
    iput-object v5, v0, Lr9/g;->o:Landroid/text/Layout$Alignment;

    .line 1272
    .line 1273
    goto :goto_1e

    .line 1274
    :pswitch_1c
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 1275
    .line 1276
    .line 1277
    move-result-object v0

    .line 1278
    iput-object v5, v0, Lr9/g;->a:Ljava/lang/String;

    .line 1279
    .line 1280
    goto :goto_1e

    .line 1281
    :pswitch_1d
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 1282
    .line 1283
    .line 1284
    move-result-object v0

    .line 1285
    iput-object v5, v0, Lr9/g;->u:Ljava/lang/String;

    .line 1286
    .line 1287
    goto :goto_1e

    .line 1288
    :pswitch_1e
    invoke-static {v0}, Lr9/e;->a(Lr9/g;)Lr9/g;

    .line 1289
    .line 1290
    .line 1291
    move-result-object v0

    .line 1292
    const-string v6, "italic"

    .line 1293
    .line 1294
    invoke-virtual {v6, v5}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 1295
    .line 1296
    .line 1297
    move-result v5

    .line 1298
    iput v5, v0, Lr9/g;->i:I

    .line 1299
    .line 1300
    :cond_41
    :goto_1e
    add-int/lit8 v4, v4, 0x1

    .line 1301
    .line 1302
    goto/16 :goto_0

    .line 1303
    .line 1304
    :cond_42
    return-object v0

    .line 1305
    :sswitch_data_0
    .sparse-switch
        -0x5c71855e -> :sswitch_10
        -0x4cd540d6 -> :sswitch_f
        -0x48ff636d -> :sswitch_e
        -0x3f826a28 -> :sswitch_d
        -0x3c1e50da -> :sswitch_c
        -0x3468fa43 -> :sswitch_b
        -0x2bc67c59 -> :sswitch_a
        0xd1b -> :sswitch_9
        0x3595da -> :sswitch_8
        0x5a72f63 -> :sswitch_7
        0x6855ce1 -> :sswitch_6
        0x6909352 -> :sswitch_5
        0x15caa0f0 -> :sswitch_4
        0x36e741c9 -> :sswitch_3
        0x42841923 -> :sswitch_2
        0x4cb7f6d5 -> :sswitch_1
        0x6899f5a4 -> :sswitch_0
    .end sparse-switch

    .line 1306
    .line 1307
    .line 1308
    .line 1309
    .line 1310
    .line 1311
    .line 1312
    .line 1313
    .line 1314
    .line 1315
    .line 1316
    .line 1317
    .line 1318
    .line 1319
    .line 1320
    .line 1321
    .line 1322
    .line 1323
    .line 1324
    .line 1325
    .line 1326
    .line 1327
    .line 1328
    .line 1329
    .line 1330
    .line 1331
    .line 1332
    .line 1333
    .line 1334
    .line 1335
    .line 1336
    .line 1337
    .line 1338
    .line 1339
    .line 1340
    .line 1341
    .line 1342
    .line 1343
    .line 1344
    .line 1345
    .line 1346
    .line 1347
    .line 1348
    .line 1349
    .line 1350
    .line 1351
    .line 1352
    .line 1353
    .line 1354
    .line 1355
    .line 1356
    .line 1357
    .line 1358
    .line 1359
    .line 1360
    .line 1361
    .line 1362
    .line 1363
    .line 1364
    .line 1365
    .line 1366
    .line 1367
    .line 1368
    .line 1369
    .line 1370
    .line 1371
    .line 1372
    .line 1373
    .line 1374
    .line 1375
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_18
        :pswitch_17
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_0
    .end packed-switch

    .line 1376
    .line 1377
    .line 1378
    .line 1379
    .line 1380
    .line 1381
    .line 1382
    .line 1383
    .line 1384
    .line 1385
    .line 1386
    .line 1387
    .line 1388
    .line 1389
    .line 1390
    .line 1391
    .line 1392
    .line 1393
    .line 1394
    .line 1395
    .line 1396
    .line 1397
    .line 1398
    .line 1399
    .line 1400
    .line 1401
    .line 1402
    .line 1403
    .line 1404
    .line 1405
    .line 1406
    .line 1407
    .line 1408
    .line 1409
    .line 1410
    .line 1411
    .line 1412
    .line 1413
    :sswitch_data_1
    .sparse-switch
        -0x514d33ab -> :sswitch_15
        0x188db -> :sswitch_14
        0x32a007 -> :sswitch_13
        0x677c21c -> :sswitch_12
        0x68ac462 -> :sswitch_11
    .end sparse-switch

    .line 1414
    .line 1415
    .line 1416
    .line 1417
    .line 1418
    .line 1419
    .line 1420
    .line 1421
    .line 1422
    .line 1423
    .line 1424
    .line 1425
    .line 1426
    .line 1427
    .line 1428
    .line 1429
    .line 1430
    .line 1431
    .line 1432
    .line 1433
    .line 1434
    .line 1435
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_2
        :pswitch_1
    .end packed-switch

    .line 1436
    .line 1437
    .line 1438
    .line 1439
    .line 1440
    .line 1441
    .line 1442
    .line 1443
    .line 1444
    .line 1445
    .line 1446
    .line 1447
    .line 1448
    .line 1449
    :sswitch_data_2
    .sparse-switch
        -0x24de7f50 -> :sswitch_1b
        -0x187eb37f -> :sswitch_1a
        -0xeee99f9 -> :sswitch_19
        -0x81c562c -> :sswitch_18
        0x2e06d1 -> :sswitch_17
        0x36452d -> :sswitch_16
    .end sparse-switch

    .line 1450
    .line 1451
    .line 1452
    .line 1453
    .line 1454
    .line 1455
    .line 1456
    .line 1457
    .line 1458
    .line 1459
    .line 1460
    .line 1461
    .line 1462
    .line 1463
    .line 1464
    .line 1465
    .line 1466
    .line 1467
    .line 1468
    .line 1469
    .line 1470
    .line 1471
    .line 1472
    .line 1473
    .line 1474
    .line 1475
    :pswitch_data_2
    .packed-switch 0x0
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_f
        :pswitch_c
    .end packed-switch

    .line 1476
    .line 1477
    .line 1478
    .line 1479
    .line 1480
    .line 1481
    .line 1482
    .line 1483
    .line 1484
    .line 1485
    .line 1486
    .line 1487
    .line 1488
    .line 1489
    .line 1490
    .line 1491
    :sswitch_data_3
    .sparse-switch
        -0x57195dd5 -> :sswitch_1f
        -0x3d363934 -> :sswitch_1e
        0x36723ff0 -> :sswitch_1d
        0x641ec051 -> :sswitch_1c
    .end sparse-switch

    .line 1492
    .line 1493
    .line 1494
    .line 1495
    .line 1496
    .line 1497
    .line 1498
    .line 1499
    .line 1500
    .line 1501
    .line 1502
    .line 1503
    .line 1504
    .line 1505
    .line 1506
    .line 1507
    .line 1508
    .line 1509
    :pswitch_data_3
    .packed-switch 0x0
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
    .end packed-switch

    .line 1510
    .line 1511
    .line 1512
    .line 1513
    .line 1514
    .line 1515
    .line 1516
    .line 1517
    .line 1518
    .line 1519
    .line 1520
    .line 1521
    :sswitch_data_4
    .sparse-switch
        -0x514d33ab -> :sswitch_24
        0x188db -> :sswitch_23
        0x32a007 -> :sswitch_22
        0x677c21c -> :sswitch_21
        0x68ac462 -> :sswitch_20
    .end sparse-switch

    .line 1522
    .line 1523
    .line 1524
    .line 1525
    .line 1526
    .line 1527
    .line 1528
    .line 1529
    .line 1530
    .line 1531
    .line 1532
    .line 1533
    .line 1534
    .line 1535
    .line 1536
    .line 1537
    .line 1538
    .line 1539
    .line 1540
    .line 1541
    .line 1542
    .line 1543
    :pswitch_data_4
    .packed-switch 0x0
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_1a
        :pswitch_19
    .end packed-switch
.end method

.method public static k(Ljava/lang/String;Lr9/d;)J
    .locals 13

    .line 1
    sget-object v0, Lr9/e;->e:Ljava/util/regex/Pattern;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0}, Ljava/util/regex/Matcher;->matches()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    const/4 v2, 0x4

    .line 12
    const/4 v3, 0x3

    .line 13
    const-wide v4, 0x412e848000000000L    # 1000000.0

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    const/4 v6, 0x2

    .line 19
    const/4 v7, 0x1

    .line 20
    if-eqz v1, :cond_3

    .line 21
    .line 22
    invoke-virtual {v0, v7}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    invoke-static {p0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 30
    .line 31
    .line 32
    move-result-wide v7

    .line 33
    const-wide/16 v9, 0xe10

    .line 34
    .line 35
    mul-long/2addr v7, v9

    .line 36
    long-to-double v7, v7

    .line 37
    invoke-virtual {v0, v6}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    invoke-static {p0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 45
    .line 46
    .line 47
    move-result-wide v9

    .line 48
    const-wide/16 v11, 0x3c

    .line 49
    .line 50
    mul-long/2addr v9, v11

    .line 51
    long-to-double v9, v9

    .line 52
    add-double/2addr v7, v9

    .line 53
    invoke-virtual {v0, v3}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    invoke-static {p0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 61
    .line 62
    .line 63
    move-result-wide v9

    .line 64
    long-to-double v9, v9

    .line 65
    add-double/2addr v7, v9

    .line 66
    invoke-virtual {v0, v2}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    const-wide/16 v1, 0x0

    .line 71
    .line 72
    if-eqz p0, :cond_0

    .line 73
    .line 74
    invoke-static {p0}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 75
    .line 76
    .line 77
    move-result-wide v9

    .line 78
    goto :goto_0

    .line 79
    :cond_0
    move-wide v9, v1

    .line 80
    :goto_0
    add-double/2addr v7, v9

    .line 81
    const/4 p0, 0x5

    .line 82
    invoke-virtual {v0, p0}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    if-eqz p0, :cond_1

    .line 87
    .line 88
    invoke-static {p0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 89
    .line 90
    .line 91
    move-result-wide v9

    .line 92
    long-to-float p0, v9

    .line 93
    iget v3, p1, Lr9/d;->a:F

    .line 94
    .line 95
    div-float/2addr p0, v3

    .line 96
    float-to-double v9, p0

    .line 97
    goto :goto_1

    .line 98
    :cond_1
    move-wide v9, v1

    .line 99
    :goto_1
    add-double/2addr v7, v9

    .line 100
    const/4 p0, 0x6

    .line 101
    invoke-virtual {v0, p0}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    if-eqz p0, :cond_2

    .line 106
    .line 107
    invoke-static {p0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 108
    .line 109
    .line 110
    move-result-wide v0

    .line 111
    long-to-double v0, v0

    .line 112
    iget p0, p1, Lr9/d;->b:I

    .line 113
    .line 114
    int-to-double v2, p0

    .line 115
    div-double/2addr v0, v2

    .line 116
    iget p0, p1, Lr9/d;->a:F

    .line 117
    .line 118
    float-to-double p0, p0

    .line 119
    div-double v1, v0, p0

    .line 120
    .line 121
    :cond_2
    add-double/2addr v7, v1

    .line 122
    mul-double/2addr v7, v4

    .line 123
    double-to-long p0, v7

    .line 124
    return-wide p0

    .line 125
    :cond_3
    sget-object v0, Lr9/e;->f:Ljava/util/regex/Pattern;

    .line 126
    .line 127
    invoke-virtual {v0, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    invoke-virtual {v0}, Ljava/util/regex/Matcher;->matches()Z

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    if-eqz v1, :cond_9

    .line 136
    .line 137
    invoke-virtual {v0, v7}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 142
    .line 143
    .line 144
    invoke-static {p0}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 145
    .line 146
    .line 147
    move-result-wide v8

    .line 148
    invoke-virtual {v0, v6}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 153
    .line 154
    .line 155
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 156
    .line 157
    .line 158
    move-result v0

    .line 159
    const/4 v1, -0x1

    .line 160
    sparse-switch v0, :sswitch_data_0

    .line 161
    .line 162
    .line 163
    :goto_2
    move v2, v1

    .line 164
    goto :goto_3

    .line 165
    :sswitch_0
    const-string v0, "ms"

    .line 166
    .line 167
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    move-result p0

    .line 171
    if-nez p0, :cond_8

    .line 172
    .line 173
    goto :goto_2

    .line 174
    :sswitch_1
    const-string v0, "t"

    .line 175
    .line 176
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result p0

    .line 180
    if-nez p0, :cond_4

    .line 181
    .line 182
    goto :goto_2

    .line 183
    :cond_4
    move v2, v3

    .line 184
    goto :goto_3

    .line 185
    :sswitch_2
    const-string v0, "m"

    .line 186
    .line 187
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 188
    .line 189
    .line 190
    move-result p0

    .line 191
    if-nez p0, :cond_5

    .line 192
    .line 193
    goto :goto_2

    .line 194
    :cond_5
    move v2, v6

    .line 195
    goto :goto_3

    .line 196
    :sswitch_3
    const-string v0, "h"

    .line 197
    .line 198
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    move-result p0

    .line 202
    if-nez p0, :cond_6

    .line 203
    .line 204
    goto :goto_2

    .line 205
    :cond_6
    move v2, v7

    .line 206
    goto :goto_3

    .line 207
    :sswitch_4
    const-string v0, "f"

    .line 208
    .line 209
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 210
    .line 211
    .line 212
    move-result p0

    .line 213
    if-nez p0, :cond_7

    .line 214
    .line 215
    goto :goto_2

    .line 216
    :cond_7
    const/4 v2, 0x0

    .line 217
    :cond_8
    :goto_3
    packed-switch v2, :pswitch_data_0

    .line 218
    .line 219
    .line 220
    goto :goto_6

    .line 221
    :pswitch_0
    const-wide p0, 0x408f400000000000L    # 1000.0

    .line 222
    .line 223
    .line 224
    .line 225
    .line 226
    :goto_4
    div-double/2addr v8, p0

    .line 227
    goto :goto_6

    .line 228
    :pswitch_1
    iget p0, p1, Lr9/d;->c:I

    .line 229
    .line 230
    int-to-double p0, p0

    .line 231
    goto :goto_4

    .line 232
    :pswitch_2
    const-wide/high16 p0, 0x404e000000000000L    # 60.0

    .line 233
    .line 234
    :goto_5
    mul-double/2addr v8, p0

    .line 235
    goto :goto_6

    .line 236
    :pswitch_3
    const-wide p0, 0x40ac200000000000L    # 3600.0

    .line 237
    .line 238
    .line 239
    .line 240
    .line 241
    goto :goto_5

    .line 242
    :pswitch_4
    iget p0, p1, Lr9/d;->a:F

    .line 243
    .line 244
    float-to-double p0, p0

    .line 245
    goto :goto_4

    .line 246
    :goto_6
    mul-double/2addr v8, v4

    .line 247
    double-to-long p0, v8

    .line 248
    return-wide p0

    .line 249
    :cond_9
    new-instance p1, Ll9/f;

    .line 250
    .line 251
    const-string v0, "Malformed time expression: "

    .line 252
    .line 253
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 254
    .line 255
    .line 256
    move-result-object p0

    .line 257
    invoke-direct {p1, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 258
    .line 259
    .line 260
    throw p1

    .line 261
    :sswitch_data_0
    .sparse-switch
        0x66 -> :sswitch_4
        0x68 -> :sswitch_3
        0x6d -> :sswitch_2
        0x74 -> :sswitch_1
        0xda6 -> :sswitch_0
    .end sparse-switch

    .line 262
    .line 263
    .line 264
    .line 265
    .line 266
    .line 267
    .line 268
    .line 269
    .line 270
    .line 271
    .line 272
    .line 273
    .line 274
    .line 275
    .line 276
    .line 277
    .line 278
    .line 279
    .line 280
    .line 281
    .line 282
    .line 283
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static l(Lorg/xmlpull/v1/XmlPullParser;)Lb8/i;
    .locals 6

    .line 1
    const-string v0, "extent"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lw7/a;->r(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const/4 v0, 0x0

    .line 8
    if-nez p0, :cond_0

    .line 9
    .line 10
    return-object v0

    .line 11
    :cond_0
    sget-object v1, Lr9/e;->j:Ljava/util/regex/Pattern;

    .line 12
    .line 13
    invoke-virtual {v1, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-virtual {v1}, Ljava/util/regex/Matcher;->matches()Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    const-string v3, "TtmlParser"

    .line 22
    .line 23
    if-nez v2, :cond_1

    .line 24
    .line 25
    const-string v1, "Ignoring non-pixel tts extent: "

    .line 26
    .line 27
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-static {v3, p0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    return-object v0

    .line 35
    :cond_1
    const/4 v2, 0x1

    .line 36
    :try_start_0
    invoke-virtual {v1, v2}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 41
    .line 42
    .line 43
    invoke-static {v2}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    const/4 v4, 0x2

    .line 48
    invoke-virtual {v1, v4}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    invoke-static {v1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    new-instance v4, Lb8/i;

    .line 60
    .line 61
    const/4 v5, 0x7

    .line 62
    invoke-direct {v4, v2, v1, v5}, Lb8/i;-><init>(III)V
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 63
    .line 64
    .line 65
    return-object v4

    .line 66
    :catch_0
    const-string v1, "Ignoring malformed tts extent: "

    .line 67
    .line 68
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-static {v3, p0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    return-object v0
.end method


# virtual methods
.method public final b([BII)Ll9/d;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    :try_start_0
    iget-object v0, v0, Lr9/e;->d:Lorg/xmlpull/v1/XmlPullParserFactory;

    .line 4
    .line 5
    invoke-virtual {v0}, Lorg/xmlpull/v1/XmlPullParserFactory;->newPullParser()Lorg/xmlpull/v1/XmlPullParser;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    new-instance v2, Ljava/util/HashMap;

    .line 10
    .line 11
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 12
    .line 13
    .line 14
    new-instance v5, Ljava/util/HashMap;

    .line 15
    .line 16
    invoke-direct {v5}, Ljava/util/HashMap;-><init>()V

    .line 17
    .line 18
    .line 19
    new-instance v6, Ljava/util/HashMap;

    .line 20
    .line 21
    invoke-direct {v6}, Ljava/util/HashMap;-><init>()V

    .line 22
    .line 23
    .line 24
    const-string v0, ""

    .line 25
    .line 26
    new-instance v7, Lr9/f;

    .line 27
    .line 28
    const-string v8, ""

    .line 29
    .line 30
    const v16, -0x800001

    .line 31
    .line 32
    .line 33
    const/high16 v17, -0x80000000

    .line 34
    .line 35
    const v9, -0x800001

    .line 36
    .line 37
    .line 38
    const v10, -0x800001

    .line 39
    .line 40
    .line 41
    const/high16 v11, -0x80000000

    .line 42
    .line 43
    const/high16 v12, -0x80000000

    .line 44
    .line 45
    const v13, -0x800001

    .line 46
    .line 47
    .line 48
    const v14, -0x800001

    .line 49
    .line 50
    .line 51
    const/high16 v15, -0x80000000

    .line 52
    .line 53
    invoke-direct/range {v7 .. v17}, Lr9/f;-><init>(Ljava/lang/String;FFIIFFIFI)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v5, v0, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    new-instance v0, Ljava/io/ByteArrayInputStream;

    .line 60
    .line 61
    move-object/from16 v3, p1

    .line 62
    .line 63
    move/from16 v4, p2

    .line 64
    .line 65
    move/from16 v7, p3

    .line 66
    .line 67
    invoke-direct {v0, v3, v4, v7}, Ljava/io/ByteArrayInputStream;-><init>([BII)V

    .line 68
    .line 69
    .line 70
    const/4 v3, 0x0

    .line 71
    invoke-interface {v1, v0, v3}, Lorg/xmlpull/v1/XmlPullParser;->setInput(Ljava/io/InputStream;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    new-instance v7, Ljava/util/ArrayDeque;

    .line 75
    .line 76
    invoke-direct {v7}, Ljava/util/ArrayDeque;-><init>()V

    .line 77
    .line 78
    .line 79
    invoke-interface {v1}, Lorg/xmlpull/v1/XmlPullParser;->getEventType()I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    sget-object v4, Lr9/e;->l:Lr9/d;

    .line 84
    .line 85
    const/16 v8, 0xf

    .line 86
    .line 87
    const/4 v9, 0x0

    .line 88
    move v10, v9

    .line 89
    move v9, v8

    .line 90
    move-object v8, v3

    .line 91
    :goto_0
    const/4 v11, 0x1

    .line 92
    if-eq v0, v11, :cond_c

    .line 93
    .line 94
    invoke-virtual {v7}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v11

    .line 98
    check-cast v11, Lr9/c;

    .line 99
    .line 100
    const/4 v12, 0x3

    .line 101
    const/4 v13, 0x2

    .line 102
    if-nez v10, :cond_9

    .line 103
    .line 104
    invoke-interface {v1}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v14
    :try_end_0
    .catch Lorg/xmlpull/v1/XmlPullParserException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1

    .line 108
    const-string v15, "tt"

    .line 109
    .line 110
    if-ne v0, v13, :cond_5

    .line 111
    .line 112
    :try_start_1
    invoke-virtual {v15, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result v0

    .line 116
    if-eqz v0, :cond_0

    .line 117
    .line 118
    invoke-static {v1}, Lr9/e;->f(Lorg/xmlpull/v1/XmlPullParser;)Lr9/d;

    .line 119
    .line 120
    .line 121
    move-result-object v4

    .line 122
    invoke-static {v1}, Lr9/e;->d(Lorg/xmlpull/v1/XmlPullParser;)I

    .line 123
    .line 124
    .line 125
    move-result v9

    .line 126
    invoke-static {v1}, Lr9/e;->l(Lorg/xmlpull/v1/XmlPullParser;)Lb8/i;

    .line 127
    .line 128
    .line 129
    move-result-object v3

    .line 130
    :cond_0
    move-object/from16 v18, v4

    .line 131
    .line 132
    move-object v4, v3

    .line 133
    move v3, v9

    .line 134
    move-object/from16 v9, v18

    .line 135
    .line 136
    invoke-static {v14}, Lr9/e;->c(Ljava/lang/String;)Z

    .line 137
    .line 138
    .line 139
    move-result v0
    :try_end_1
    .catch Lorg/xmlpull/v1/XmlPullParserException; {:try_start_1 .. :try_end_1} :catch_2
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1

    .line 140
    const-string v12, "TtmlParser"

    .line 141
    .line 142
    if-nez v0, :cond_2

    .line 143
    .line 144
    :try_start_2
    new-instance v0, Ljava/lang/StringBuilder;

    .line 145
    .line 146
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 147
    .line 148
    .line 149
    const-string v11, "Ignoring unsupported tag: "

    .line 150
    .line 151
    invoke-virtual {v0, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 152
    .line 153
    .line 154
    invoke-interface {v1}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v11

    .line 158
    invoke-virtual {v0, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 159
    .line 160
    .line 161
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    invoke-static {v12, v0}, Lw7/a;->s(Ljava/lang/String;Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    :goto_1
    add-int/lit8 v10, v10, 0x1

    .line 169
    .line 170
    :cond_1
    :goto_2
    move-object/from16 v18, v9

    .line 171
    .line 172
    move v9, v3

    .line 173
    move-object v3, v4

    .line 174
    move-object/from16 v4, v18

    .line 175
    .line 176
    goto/16 :goto_3

    .line 177
    .line 178
    :cond_2
    const-string v0, "head"

    .line 179
    .line 180
    invoke-virtual {v0, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 181
    .line 182
    .line 183
    move-result v0

    .line 184
    if-eqz v0, :cond_3

    .line 185
    .line 186
    invoke-static/range {v1 .. v6}, Lr9/e;->h(Lorg/xmlpull/v1/XmlPullParser;Ljava/util/HashMap;ILb8/i;Ljava/util/HashMap;Ljava/util/HashMap;)V
    :try_end_2
    .catch Lorg/xmlpull/v1/XmlPullParserException; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_1

    .line 187
    .line 188
    .line 189
    goto :goto_2

    .line 190
    :cond_3
    :try_start_3
    invoke-static {v1, v11, v5, v9}, Lr9/e;->i(Lorg/xmlpull/v1/XmlPullParser;Lr9/c;Ljava/util/HashMap;Lr9/d;)Lr9/c;

    .line 191
    .line 192
    .line 193
    move-result-object v0

    .line 194
    invoke-virtual {v7, v0}, Ljava/util/ArrayDeque;->push(Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    if-eqz v11, :cond_1

    .line 198
    .line 199
    iget-object v13, v11, Lr9/c;->m:Ljava/util/ArrayList;

    .line 200
    .line 201
    if-nez v13, :cond_4

    .line 202
    .line 203
    new-instance v13, Ljava/util/ArrayList;

    .line 204
    .line 205
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 206
    .line 207
    .line 208
    iput-object v13, v11, Lr9/c;->m:Ljava/util/ArrayList;

    .line 209
    .line 210
    :cond_4
    iget-object v11, v11, Lr9/c;->m:Ljava/util/ArrayList;

    .line 211
    .line 212
    invoke-virtual {v11, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_3
    .catch Ll9/f; {:try_start_3 .. :try_end_3} :catch_0
    .catch Lorg/xmlpull/v1/XmlPullParserException; {:try_start_3 .. :try_end_3} :catch_2
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_1

    .line 213
    .line 214
    .line 215
    goto :goto_2

    .line 216
    :catch_0
    move-exception v0

    .line 217
    :try_start_4
    const-string v11, "Suppressing parser error"

    .line 218
    .line 219
    invoke-static {v12, v11, v0}, Lw7/a;->z(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 220
    .line 221
    .line 222
    goto :goto_1

    .line 223
    :cond_5
    const/4 v13, 0x4

    .line 224
    if-ne v0, v13, :cond_7

    .line 225
    .line 226
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 227
    .line 228
    .line 229
    invoke-interface {v1}, Lorg/xmlpull/v1/XmlPullParser;->getText()Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object v0

    .line 233
    invoke-static {v0}, Lr9/c;->a(Ljava/lang/String;)Lr9/c;

    .line 234
    .line 235
    .line 236
    move-result-object v0

    .line 237
    iget-object v12, v11, Lr9/c;->m:Ljava/util/ArrayList;

    .line 238
    .line 239
    if-nez v12, :cond_6

    .line 240
    .line 241
    new-instance v12, Ljava/util/ArrayList;

    .line 242
    .line 243
    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 244
    .line 245
    .line 246
    iput-object v12, v11, Lr9/c;->m:Ljava/util/ArrayList;

    .line 247
    .line 248
    :cond_6
    iget-object v11, v11, Lr9/c;->m:Ljava/util/ArrayList;

    .line 249
    .line 250
    invoke-virtual {v11, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 251
    .line 252
    .line 253
    goto :goto_3

    .line 254
    :cond_7
    if-ne v0, v12, :cond_b

    .line 255
    .line 256
    invoke-interface {v1}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 257
    .line 258
    .line 259
    move-result-object v0

    .line 260
    invoke-virtual {v0, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 261
    .line 262
    .line 263
    move-result v0

    .line 264
    if-eqz v0, :cond_8

    .line 265
    .line 266
    new-instance v8, Landroidx/lifecycle/c1;

    .line 267
    .line 268
    invoke-virtual {v7}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    move-result-object v0

    .line 272
    check-cast v0, Lr9/c;

    .line 273
    .line 274
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 275
    .line 276
    .line 277
    invoke-direct {v8, v0, v2, v5, v6}, Landroidx/lifecycle/c1;-><init>(Lr9/c;Ljava/util/HashMap;Ljava/util/HashMap;Ljava/util/HashMap;)V

    .line 278
    .line 279
    .line 280
    :cond_8
    invoke-virtual {v7}, Ljava/util/ArrayDeque;->pop()Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    goto :goto_3

    .line 284
    :cond_9
    if-ne v0, v13, :cond_a

    .line 285
    .line 286
    add-int/lit8 v10, v10, 0x1

    .line 287
    .line 288
    goto :goto_3

    .line 289
    :cond_a
    if-ne v0, v12, :cond_b

    .line 290
    .line 291
    add-int/lit8 v10, v10, -0x1

    .line 292
    .line 293
    :cond_b
    :goto_3
    invoke-interface {v1}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 294
    .line 295
    .line 296
    invoke-interface {v1}, Lorg/xmlpull/v1/XmlPullParser;->getEventType()I

    .line 297
    .line 298
    .line 299
    move-result v0

    .line 300
    goto/16 :goto_0

    .line 301
    .line 302
    :cond_c
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_4
    .catch Lorg/xmlpull/v1/XmlPullParserException; {:try_start_4 .. :try_end_4} :catch_2
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_1

    .line 303
    .line 304
    .line 305
    return-object v8

    .line 306
    :catch_1
    move-exception v0

    .line 307
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 308
    .line 309
    const-string v2, "Unexpected error when reading input."

    .line 310
    .line 311
    invoke-direct {v1, v2, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 312
    .line 313
    .line 314
    throw v1

    .line 315
    :catch_2
    move-exception v0

    .line 316
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 317
    .line 318
    const-string v2, "Unable to decode source"

    .line 319
    .line 320
    invoke-direct {v1, v2, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 321
    .line 322
    .line 323
    throw v1
.end method

.method public final g([BIILl9/i;Lw7/f;)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2, p3}, Lr9/e;->b([BII)Ll9/d;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0, p4, p5}, Llp/cf;->c(Ll9/d;Ll9/i;Lw7/f;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
