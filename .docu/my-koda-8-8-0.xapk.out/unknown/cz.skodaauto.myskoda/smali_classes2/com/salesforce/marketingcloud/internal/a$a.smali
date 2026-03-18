.class public final Lcom/salesforce/marketingcloud/internal/a$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/internal/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/internal/a;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# static fields
.field public static final a:Lcom/salesforce/marketingcloud/internal/a$a;

.field private static final b:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/internal/a$a;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/internal/a$a;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/internal/a$a;->a:Lcom/salesforce/marketingcloud/internal/a$a;

    .line 7
    .line 8
    const-string v0, "Deflate"

    .line 9
    .line 10
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/internal/a$a;->b:Ljava/lang/String;

    .line 15
    .line 16
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public a(Ljava/lang/String;)Ljava/lang/String;
    .locals 9

    .line 1
    const-string p0, "input"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ljava/util/Base64;->getDecoder()Ljava/util/Base64$Decoder;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0, p1}, Ljava/util/Base64$Decoder;->decode(Ljava/lang/String;)[B

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 15
    .line 16
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 17
    .line 18
    filled-new-array {v0, v1}, [Ljava/lang/Boolean;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-eqz v1, :cond_1

    .line 35
    .line 36
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    check-cast v1, Ljava/lang/Boolean;

    .line 41
    .line 42
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    :try_start_0
    new-instance v2, Ljava/util/zip/Inflater;

    .line 47
    .line 48
    invoke-direct {v2, v1}, Ljava/util/zip/Inflater;-><init>(Z)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 49
    .line 50
    .line 51
    :try_start_1
    invoke-virtual {v2, p0}, Ljava/util/zip/Inflater;->setInput([B)V

    .line 52
    .line 53
    .line 54
    new-instance v3, Ljava/io/ByteArrayOutputStream;

    .line 55
    .line 56
    invoke-direct {v3}, Ljava/io/ByteArrayOutputStream;-><init>()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 57
    .line 58
    .line 59
    const/16 v4, 0x400

    .line 60
    .line 61
    :try_start_2
    new-array v4, v4, [B

    .line 62
    .line 63
    :goto_1
    invoke-virtual {v2}, Ljava/util/zip/Inflater;->finished()Z

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    if-nez v5, :cond_0

    .line 68
    .line 69
    invoke-virtual {v2, v4}, Ljava/util/zip/Inflater;->inflate([B)I

    .line 70
    .line 71
    .line 72
    move-result v5

    .line 73
    const/4 v6, 0x0

    .line 74
    invoke-virtual {v3, v4, v6, v5}, Ljava/io/ByteArrayOutputStream;->write([BII)V

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :catchall_0
    move-exception v4

    .line 79
    goto :goto_2

    .line 80
    :cond_0
    invoke-virtual {v3}, Ljava/io/ByteArrayOutputStream;->toString()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    const-string v5, "toString(...)"

    .line 85
    .line 86
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    sget-object v5, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    .line 90
    .line 91
    sget-object v6, Lcom/salesforce/marketingcloud/internal/a$a;->b:Ljava/lang/String;

    .line 92
    .line 93
    new-instance v7, Lcom/salesforce/marketingcloud/internal/a$a$a;

    .line 94
    .line 95
    invoke-direct {v7, v1, v4}, Lcom/salesforce/marketingcloud/internal/a$a$a;-><init>(ZLjava/lang/String;)V

    .line 96
    .line 97
    .line 98
    const/4 v8, 0x0

    .line 99
    invoke-virtual {v5, v6, v8, v7}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 100
    .line 101
    .line 102
    :try_start_3
    invoke-virtual {v3}, Ljava/io/ByteArrayOutputStream;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 103
    .line 104
    .line 105
    :try_start_4
    invoke-virtual {v2}, Ljava/util/zip/Inflater;->end()V
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_0

    .line 106
    .line 107
    .line 108
    return-object v4

    .line 109
    :catch_0
    move-exception v2

    .line 110
    goto :goto_4

    .line 111
    :catchall_1
    move-exception v3

    .line 112
    goto :goto_3

    .line 113
    :goto_2
    :try_start_5
    throw v4
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 114
    :catchall_2
    move-exception v5

    .line 115
    :try_start_6
    invoke-static {v3, v4}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 116
    .line 117
    .line 118
    throw v5
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 119
    :goto_3
    :try_start_7
    invoke-virtual {v2}, Ljava/util/zip/Inflater;->end()V

    .line 120
    .line 121
    .line 122
    throw v3
    :try_end_7
    .catch Ljava/lang/Exception; {:try_start_7 .. :try_end_7} :catch_0

    .line 123
    :goto_4
    sget-object v3, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    .line 124
    .line 125
    sget-object v4, Lcom/salesforce/marketingcloud/internal/a$a;->b:Ljava/lang/String;

    .line 126
    .line 127
    new-instance v5, Lcom/salesforce/marketingcloud/internal/a$a$b;

    .line 128
    .line 129
    invoke-direct {v5, v1}, Lcom/salesforce/marketingcloud/internal/a$a$b;-><init>(Z)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v3, v4, v2, v5}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 133
    .line 134
    .line 135
    goto :goto_0

    .line 136
    :cond_1
    new-instance p0, Lcom/salesforce/marketingcloud/push/c;

    .line 137
    .line 138
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/push/c;-><init>(Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    throw p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of p0, p1, Lcom/salesforce/marketingcloud/internal/a$a;

    .line 6
    .line 7
    if-nez p0, :cond_1

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_1
    return v0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    const p0, 0x7860c002

    .line 2
    .line 3
    .line 4
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "Deflate"

    .line 2
    .line 3
    return-object p0
.end method
