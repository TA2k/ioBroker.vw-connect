.class Lcom/contoworks/kontocloud/uicomponents/widget/PayonTemplateHelper;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static compiler:Lxw/h;

.field private static template:Lxw/v;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lxw/h;

    .line 2
    .line 3
    new-instance v1, Lxw/e;

    .line 4
    .line 5
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    new-instance v2, Lxw/i;

    .line 9
    .line 10
    invoke-direct {v2}, Lxw/i;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-direct {v0, v1, v2}, Lxw/h;-><init>(Lxw/e;Lxw/i;)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PayonTemplateHelper;->compiler:Lxw/h;

    .line 17
    .line 18
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static renderTemplate(Landroid/content/Context;Ljava/lang/Object;I)Ljava/lang/String;
    .locals 7

    .line 1
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0, p2}, Landroid/content/res/Resources;->openRawResource(I)Ljava/io/InputStream;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :try_start_0
    invoke-static {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/PayonTemplateHelper;->streamToString(Ljava/io/InputStream;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1

    .line 13
    sget-object p2, Lcom/contoworks/kontocloud/uicomponents/widget/PayonTemplateHelper;->compiler:Lxw/h;

    .line 14
    .line 15
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    new-instance v0, Ljava/io/StringReader;

    .line 19
    .line 20
    invoke-direct {v0, p0}, Ljava/io/StringReader;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    new-instance p0, Ln1/l;

    .line 24
    .line 25
    invoke-direct {p0, p2}, Ln1/l;-><init>(Lxw/h;)V

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Ln1/l;->c:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v1, Lxw/i;

    .line 31
    .line 32
    iget-object v2, p0, Ln1/l;->d:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v2, Ljava/lang/StringBuilder;

    .line 35
    .line 36
    iput-object v0, p0, Ln1/l;->e:Ljava/lang/Object;

    .line 37
    .line 38
    :cond_0
    :goto_0
    :try_start_1
    iget-object v0, p0, Ln1/l;->e:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v0, Ljava/io/StringReader;

    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/io/Reader;->read()I

    .line 43
    .line 44
    .line 45
    move-result v0
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0

    .line 46
    const/4 v3, -0x1

    .line 47
    const/4 v4, 0x1

    .line 48
    if-eq v0, v3, :cond_1

    .line 49
    .line 50
    int-to-char v0, v0

    .line 51
    invoke-virtual {p0, v0}, Ln1/l;->c(C)V

    .line 52
    .line 53
    .line 54
    const/16 v3, 0xa

    .line 55
    .line 56
    if-ne v0, v3, :cond_0

    .line 57
    .line 58
    iget v0, p0, Ln1/l;->b:I

    .line 59
    .line 60
    add-int/2addr v0, v4

    .line 61
    iput v0, p0, Ln1/l;->b:I

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_1
    iget v0, p0, Ln1/l;->a:I

    .line 65
    .line 66
    if-eq v0, v4, :cond_5

    .line 67
    .line 68
    const/4 v3, 0x2

    .line 69
    const/4 v5, 0x0

    .line 70
    if-eq v0, v3, :cond_3

    .line 71
    .line 72
    const/4 v3, 0x3

    .line 73
    if-eq v0, v3, :cond_2

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_2
    iget-char v0, v1, Lxw/i;->a:C

    .line 77
    .line 78
    invoke-virtual {v2, v5, v0}, Ljava/lang/StringBuilder;->insert(IC)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    iget-char v0, v1, Lxw/i;->c:C

    .line 82
    .line 83
    if-eqz v0, :cond_6

    .line 84
    .line 85
    invoke-virtual {v2, v4, v0}, Ljava/lang/StringBuilder;->insert(IC)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_3
    iget-char v0, v1, Lxw/i;->a:C

    .line 90
    .line 91
    invoke-virtual {v2, v5, v0}, Ljava/lang/StringBuilder;->insert(IC)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    iget-char v0, v1, Lxw/i;->c:C

    .line 95
    .line 96
    if-eqz v0, :cond_4

    .line 97
    .line 98
    invoke-virtual {v2, v4, v0}, Ljava/lang/StringBuilder;->insert(IC)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    :cond_4
    iget-char v0, v1, Lxw/i;->b:C

    .line 102
    .line 103
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_5
    iget-char v0, v1, Lxw/i;->a:C

    .line 108
    .line 109
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    :cond_6
    :goto_1
    iget-object v0, p0, Ln1/l;->f:Ljava/lang/Object;

    .line 113
    .line 114
    check-cast v0, Lcom/google/android/gms/internal/measurement/i4;

    .line 115
    .line 116
    invoke-virtual {v0, v2}, Lcom/google/android/gms/internal/measurement/i4;->i(Ljava/lang/StringBuilder;)V

    .line 117
    .line 118
    .line 119
    iget-object p0, p0, Ln1/l;->f:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast p0, Lcom/google/android/gms/internal/measurement/i4;

    .line 122
    .line 123
    new-instance v0, Lxw/v;

    .line 124
    .line 125
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/i4;->q()[Lxw/u;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    invoke-static {p0, v4}, Lxw/f;->a([Lxw/u;Z)V

    .line 130
    .line 131
    .line 132
    invoke-direct {v0, p0, p2}, Lxw/v;-><init>([Lxw/u;Lxw/h;)V

    .line 133
    .line 134
    .line 135
    sput-object v0, Lcom/contoworks/kontocloud/uicomponents/widget/PayonTemplateHelper;->template:Lxw/v;

    .line 136
    .line 137
    new-instance p0, Ljava/io/StringWriter;

    .line 138
    .line 139
    invoke-direct {p0}, Ljava/io/StringWriter;-><init>()V

    .line 140
    .line 141
    .line 142
    new-instance v1, Lxw/s;

    .line 143
    .line 144
    const/4 v5, 0x0

    .line 145
    const/4 v6, 0x0

    .line 146
    const/4 v3, 0x0

    .line 147
    const/4 v4, 0x0

    .line 148
    move-object v2, p1

    .line 149
    invoke-direct/range {v1 .. v6}, Lxw/s;-><init>(Ljava/lang/Object;Lxw/s;IZZ)V

    .line 150
    .line 151
    .line 152
    iget-object p1, v0, Lxw/v;->a:[Lxw/u;

    .line 153
    .line 154
    array-length p2, p1

    .line 155
    const/4 v2, 0x0

    .line 156
    :goto_2
    if-ge v2, p2, :cond_7

    .line 157
    .line 158
    aget-object v3, p1, v2

    .line 159
    .line 160
    invoke-virtual {v3, v0, v1, p0}, Lxw/u;->a(Lxw/v;Lxw/s;Ljava/io/StringWriter;)V

    .line 161
    .line 162
    .line 163
    add-int/lit8 v2, v2, 0x1

    .line 164
    .line 165
    goto :goto_2

    .line 166
    :cond_7
    invoke-virtual {p0}, Ljava/io/StringWriter;->toString()Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object p0

    .line 170
    return-object p0

    .line 171
    :catch_0
    move-exception v0

    .line 172
    move-object p0, v0

    .line 173
    new-instance p1, La8/r0;

    .line 174
    .line 175
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 176
    .line 177
    .line 178
    throw p1

    .line 179
    :catch_1
    move-exception v0

    .line 180
    move-object p0, v0

    .line 181
    new-instance p1, Ljava/lang/RuntimeException;

    .line 182
    .line 183
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 184
    .line 185
    .line 186
    throw p1
.end method

.method private static streamToString(Ljava/io/InputStream;)Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ljava/io/BufferedReader;

    .line 7
    .line 8
    new-instance v2, Ljava/io/InputStreamReader;

    .line 9
    .line 10
    invoke-direct {v2, p0}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    .line 11
    .line 12
    .line 13
    invoke-direct {v1, v2}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    .line 14
    .line 15
    .line 16
    :goto_0
    :try_start_0
    invoke-virtual {v1}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string p0, "line.separator"

    .line 26
    .line 27
    invoke-static {p0}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :catchall_0
    move-exception p0

    .line 36
    goto :goto_1

    .line 37
    :cond_0
    invoke-virtual {v1}, Ljava/io/BufferedReader;->close()V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0

    .line 45
    :goto_1
    invoke-virtual {v1}, Ljava/io/BufferedReader;->close()V

    .line 46
    .line 47
    .line 48
    throw p0
.end method
