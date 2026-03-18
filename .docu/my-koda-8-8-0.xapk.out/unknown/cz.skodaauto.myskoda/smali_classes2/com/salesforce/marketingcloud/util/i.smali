.class public Lcom/salesforce/marketingcloud/util/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field private static final f:B = 0xdt

.field private static final g:B = 0xat


# instance fields
.field final a:Ljava/nio/charset/Charset;

.field private final b:Ljava/io/InputStream;

.field private c:[B

.field private d:I

.field private e:I


# direct methods
.method public constructor <init>(Ljava/io/InputStream;)V
    .locals 1

    const/16 v0, 0x2000

    .line 1
    invoke-direct {p0, p1, v0}, Lcom/salesforce/marketingcloud/util/i;-><init>(Ljava/io/InputStream;I)V

    return-void
.end method

.method public constructor <init>(Ljava/io/InputStream;I)V
    .locals 1

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/util/e;->a:Ljava/nio/charset/Charset;

    invoke-direct {p0, p1, p2, v0}, Lcom/salesforce/marketingcloud/util/i;-><init>(Ljava/io/InputStream;ILjava/nio/charset/Charset;)V

    return-void
.end method

.method public constructor <init>(Ljava/io/InputStream;ILjava/nio/charset/Charset;)V
    .locals 1

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-eqz p1, :cond_4

    if-eqz p3, :cond_3

    if-ltz p2, :cond_2

    .line 5
    sget-object v0, Lcom/salesforce/marketingcloud/util/e;->a:Ljava/nio/charset/Charset;

    invoke-virtual {p3, v0}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    sget-object v0, Lcom/salesforce/marketingcloud/util/e;->c:Ljava/nio/charset/Charset;

    invoke-virtual {p3, v0}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    sget-object v0, Lcom/salesforce/marketingcloud/util/e;->b:Ljava/nio/charset/Charset;

    invoke-virtual {p3, v0}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Unsupported encoding"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 7
    :cond_1
    :goto_0
    iput-object p1, p0, Lcom/salesforce/marketingcloud/util/i;->b:Ljava/io/InputStream;

    .line 8
    iput-object p3, p0, Lcom/salesforce/marketingcloud/util/i;->a:Ljava/nio/charset/Charset;

    .line 9
    new-array p1, p2, [B

    iput-object p1, p0, Lcom/salesforce/marketingcloud/util/i;->c:[B

    return-void

    .line 10
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "capacity <= 0"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 11
    :cond_3
    new-instance p0, Ljava/lang/NullPointerException;

    const-string p1, "charset == null"

    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 12
    :cond_4
    new-instance p0, Ljava/lang/NullPointerException;

    const-string p1, "in == null"

    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public constructor <init>(Ljava/io/InputStream;Ljava/nio/charset/Charset;)V
    .locals 1

    const/16 v0, 0x2000

    .line 3
    invoke-direct {p0, p1, v0, p2}, Lcom/salesforce/marketingcloud/util/i;-><init>(Ljava/io/InputStream;ILjava/nio/charset/Charset;)V

    return-void
.end method

.method private a()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/i;->b:Ljava/io/InputStream;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/util/i;->c:[B

    .line 4
    .line 5
    array-length v2, v1

    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-virtual {v0, v1, v3, v2}, Ljava/io/InputStream;->read([BII)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/4 v1, -0x1

    .line 12
    if-eq v0, v1, :cond_0

    .line 13
    .line 14
    iput v3, p0, Lcom/salesforce/marketingcloud/util/i;->d:I

    .line 15
    .line 16
    iput v0, p0, Lcom/salesforce/marketingcloud/util/i;->e:I

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    new-instance p0, Ljava/io/EOFException;

    .line 20
    .line 21
    invoke-direct {p0}, Ljava/io/EOFException;-><init>()V

    .line 22
    .line 23
    .line 24
    throw p0
.end method


# virtual methods
.method public b()Z
    .locals 1

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/util/i;->e:I

    .line 2
    .line 3
    const/4 v0, -0x1

    .line 4
    if-ne p0, v0, :cond_0

    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    return p0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return p0
.end method

.method public c()I
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/util/i;->d()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    :try_start_0
    invoke-static {p0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 6
    .line 7
    .line 8
    move-result p0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 9
    return p0

    .line 10
    :catch_0
    new-instance v0, Ljava/io/IOException;

    .line 11
    .line 12
    const-string v1, "expected an int but was \""

    .line 13
    .line 14
    const-string v2, "\""

    .line 15
    .line 16
    invoke-static {v1, p0, v2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-direct {v0, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw v0
.end method

.method public close()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/i;->b:Ljava/io/InputStream;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/util/i;->c:[B

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    iput-object v1, p0, Lcom/salesforce/marketingcloud/util/i;->c:[B

    .line 10
    .line 11
    iget-object p0, p0, Lcom/salesforce/marketingcloud/util/i;->b:Ljava/io/InputStream;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/io/InputStream;->close()V

    .line 14
    .line 15
    .line 16
    goto :goto_0

    .line 17
    :catchall_0
    move-exception p0

    .line 18
    goto :goto_1

    .line 19
    :cond_0
    :goto_0
    monitor-exit v0

    .line 20
    return-void

    .line 21
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    throw p0
.end method

.method public d()Ljava/lang/String;
    .locals 7

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/util/i;->b:Ljava/io/InputStream;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/util/i;->c:[B

    .line 5
    .line 6
    if-eqz v1, :cond_7

    .line 7
    .line 8
    iget v1, p0, Lcom/salesforce/marketingcloud/util/i;->d:I

    .line 9
    .line 10
    iget v2, p0, Lcom/salesforce/marketingcloud/util/i;->e:I

    .line 11
    .line 12
    if-lt v1, v2, :cond_0

    .line 13
    .line 14
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/util/i;->a()V

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    :catchall_0
    move-exception p0

    .line 19
    goto/16 :goto_4

    .line 20
    .line 21
    :cond_0
    :goto_0
    iget v1, p0, Lcom/salesforce/marketingcloud/util/i;->d:I

    .line 22
    .line 23
    :goto_1
    iget v2, p0, Lcom/salesforce/marketingcloud/util/i;->e:I

    .line 24
    .line 25
    const/16 v3, 0xa

    .line 26
    .line 27
    if-eq v1, v2, :cond_3

    .line 28
    .line 29
    iget-object v2, p0, Lcom/salesforce/marketingcloud/util/i;->c:[B

    .line 30
    .line 31
    aget-byte v4, v2, v1

    .line 32
    .line 33
    if-ne v4, v3, :cond_2

    .line 34
    .line 35
    iget v3, p0, Lcom/salesforce/marketingcloud/util/i;->d:I

    .line 36
    .line 37
    if-eq v1, v3, :cond_1

    .line 38
    .line 39
    add-int/lit8 v4, v1, -0x1

    .line 40
    .line 41
    aget-byte v5, v2, v4

    .line 42
    .line 43
    const/16 v6, 0xd

    .line 44
    .line 45
    if-ne v5, v6, :cond_1

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_1
    move v4, v1

    .line 49
    :goto_2
    new-instance v5, Ljava/lang/String;

    .line 50
    .line 51
    sub-int/2addr v4, v3

    .line 52
    iget-object v6, p0, Lcom/salesforce/marketingcloud/util/i;->a:Ljava/nio/charset/Charset;

    .line 53
    .line 54
    invoke-direct {v5, v2, v3, v4, v6}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 55
    .line 56
    .line 57
    add-int/lit8 v1, v1, 0x1

    .line 58
    .line 59
    iput v1, p0, Lcom/salesforce/marketingcloud/util/i;->d:I

    .line 60
    .line 61
    monitor-exit v0

    .line 62
    return-object v5

    .line 63
    :cond_2
    add-int/lit8 v1, v1, 0x1

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_3
    new-instance v1, Lcom/salesforce/marketingcloud/util/i$a;

    .line 67
    .line 68
    iget v2, p0, Lcom/salesforce/marketingcloud/util/i;->e:I

    .line 69
    .line 70
    iget v4, p0, Lcom/salesforce/marketingcloud/util/i;->d:I

    .line 71
    .line 72
    sub-int/2addr v2, v4

    .line 73
    add-int/lit8 v2, v2, 0x50

    .line 74
    .line 75
    invoke-direct {v1, p0, v2}, Lcom/salesforce/marketingcloud/util/i$a;-><init>(Lcom/salesforce/marketingcloud/util/i;I)V

    .line 76
    .line 77
    .line 78
    :cond_4
    iget-object v2, p0, Lcom/salesforce/marketingcloud/util/i;->c:[B

    .line 79
    .line 80
    iget v4, p0, Lcom/salesforce/marketingcloud/util/i;->d:I

    .line 81
    .line 82
    iget v5, p0, Lcom/salesforce/marketingcloud/util/i;->e:I

    .line 83
    .line 84
    sub-int/2addr v5, v4

    .line 85
    invoke-virtual {v1, v2, v4, v5}, Ljava/io/ByteArrayOutputStream;->write([BII)V

    .line 86
    .line 87
    .line 88
    const/4 v2, -0x1

    .line 89
    iput v2, p0, Lcom/salesforce/marketingcloud/util/i;->e:I

    .line 90
    .line 91
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/util/i;->a()V

    .line 92
    .line 93
    .line 94
    iget v2, p0, Lcom/salesforce/marketingcloud/util/i;->d:I

    .line 95
    .line 96
    :goto_3
    iget v4, p0, Lcom/salesforce/marketingcloud/util/i;->e:I

    .line 97
    .line 98
    if-eq v2, v4, :cond_4

    .line 99
    .line 100
    iget-object v4, p0, Lcom/salesforce/marketingcloud/util/i;->c:[B

    .line 101
    .line 102
    aget-byte v5, v4, v2

    .line 103
    .line 104
    if-ne v5, v3, :cond_6

    .line 105
    .line 106
    iget v3, p0, Lcom/salesforce/marketingcloud/util/i;->d:I

    .line 107
    .line 108
    if-eq v2, v3, :cond_5

    .line 109
    .line 110
    sub-int v5, v2, v3

    .line 111
    .line 112
    invoke-virtual {v1, v4, v3, v5}, Ljava/io/ByteArrayOutputStream;->write([BII)V

    .line 113
    .line 114
    .line 115
    :cond_5
    add-int/lit8 v2, v2, 0x1

    .line 116
    .line 117
    iput v2, p0, Lcom/salesforce/marketingcloud/util/i;->d:I

    .line 118
    .line 119
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/util/i$a;->toString()Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    monitor-exit v0

    .line 124
    return-object p0

    .line 125
    :cond_6
    add-int/lit8 v2, v2, 0x1

    .line 126
    .line 127
    goto :goto_3

    .line 128
    :cond_7
    new-instance p0, Ljava/io/IOException;

    .line 129
    .line 130
    const-string v1, "LineReader is closed"

    .line 131
    .line 132
    invoke-direct {p0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    throw p0

    .line 136
    :goto_4
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 137
    throw p0
.end method
