.class public final synthetic Lum/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Callable;


# instance fields
.field public final synthetic a:Ljava/lang/ref/WeakReference;

.field public final synthetic b:Landroid/content/Context;

.field public final synthetic c:I

.field public final synthetic d:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/ref/WeakReference;Landroid/content/Context;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lum/b;->a:Ljava/lang/ref/WeakReference;

    .line 5
    .line 6
    iput-object p2, p0, Lum/b;->b:Landroid/content/Context;

    .line 7
    .line 8
    iput p3, p0, Lum/b;->c:I

    .line 9
    .line 10
    iput-object p4, p0, Lum/b;->d:Ljava/lang/String;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final call()Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lum/b;->c:I

    .line 2
    .line 3
    iget-object v1, p0, Lum/b;->a:Ljava/lang/ref/WeakReference;

    .line 4
    .line 5
    invoke-virtual {v1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    check-cast v1, Landroid/content/Context;

    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    iget-object v1, p0, Lum/b;->b:Landroid/content/Context;

    .line 15
    .line 16
    :goto_0
    iget-object p0, p0, Lum/b;->d:Ljava/lang/String;

    .line 17
    .line 18
    if-nez p0, :cond_1

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    goto :goto_1

    .line 22
    :cond_1
    sget-object v2, Lan/e;->b:Lan/e;

    .line 23
    .line 24
    invoke-virtual {v2, p0}, Lan/e;->a(Ljava/lang/String;)Lum/a;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    :goto_1
    if-eqz v2, :cond_2

    .line 29
    .line 30
    new-instance p0, Lum/n;

    .line 31
    .line 32
    invoke-direct {p0, v2}, Lum/n;-><init>(Lum/a;)V

    .line 33
    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_2
    :try_start_0
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    invoke-virtual {v2, v0}, Landroid/content/res/Resources;->openRawResource(I)Ljava/io/InputStream;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-static {v0}, Lu01/b;->g(Ljava/io/InputStream;)Lu01/s;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    invoke-static {v0}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    sget-object v2, Lum/d;->c:[B

    .line 53
    .line 54
    invoke-static {v0, v2}, Lum/d;->c(Lu01/b0;[B)Ljava/lang/Boolean;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    const/4 v3, 0x3

    .line 63
    if-eqz v2, :cond_3

    .line 64
    .line 65
    new-instance v2, Ljava/util/zip/ZipInputStream;

    .line 66
    .line 67
    new-instance v4, Lcx0/a;

    .line 68
    .line 69
    invoke-direct {v4, v0, v3}, Lcx0/a;-><init>(Ljava/lang/Object;I)V

    .line 70
    .line 71
    .line 72
    invoke-direct {v2, v4}, Ljava/util/zip/ZipInputStream;-><init>(Ljava/io/InputStream;)V
    :try_end_0
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_0 .. :try_end_0} :catch_1

    .line 73
    .line 74
    .line 75
    :try_start_1
    invoke-static {v1, v2, p0}, Lum/d;->b(Landroid/content/Context;Ljava/util/zip/ZipInputStream;Ljava/lang/String;)Lum/n;

    .line 76
    .line 77
    .line 78
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 79
    :try_start_2
    invoke-static {v2}, Lgn/h;->b(Ljava/io/Closeable;)V

    .line 80
    .line 81
    .line 82
    return-object p0

    .line 83
    :catchall_0
    move-exception p0

    .line 84
    invoke-static {v2}, Lgn/h;->b(Ljava/io/Closeable;)V

    .line 85
    .line 86
    .line 87
    throw p0

    .line 88
    :cond_3
    sget-object v1, Lum/d;->d:[B

    .line 89
    .line 90
    invoke-static {v0, v1}, Lum/d;->c(Lu01/b0;[B)Ljava/lang/Boolean;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 95
    .line 96
    .line 97
    move-result v1
    :try_end_2
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_2 .. :try_end_2} :catch_1

    .line 98
    const/4 v2, 0x1

    .line 99
    if-eqz v1, :cond_4

    .line 100
    .line 101
    :try_start_3
    new-instance v1, Ljava/util/zip/GZIPInputStream;

    .line 102
    .line 103
    new-instance v4, Lcx0/a;

    .line 104
    .line 105
    invoke-direct {v4, v0, v3}, Lcx0/a;-><init>(Ljava/lang/Object;I)V

    .line 106
    .line 107
    .line 108
    invoke-direct {v1, v4}, Ljava/util/zip/GZIPInputStream;-><init>(Ljava/io/InputStream;)V

    .line 109
    .line 110
    .line 111
    invoke-static {v1}, Lu01/b;->g(Ljava/io/InputStream;)Lu01/s;

    .line 112
    .line 113
    .line 114
    move-result-object v0

    .line 115
    invoke-static {v0}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    sget-object v1, Lfn/a;->h:[Ljava/lang/String;

    .line 120
    .line 121
    new-instance v1, Lfn/b;

    .line 122
    .line 123
    invoke-direct {v1, v0}, Lfn/b;-><init>(Lu01/b0;)V

    .line 124
    .line 125
    .line 126
    invoke-static {v1, p0, v2}, Lum/d;->a(Lfn/b;Ljava/lang/String;Z)Lum/n;

    .line 127
    .line 128
    .line 129
    move-result-object p0
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_0
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_3 .. :try_end_3} :catch_1

    .line 130
    return-object p0

    .line 131
    :catch_0
    move-exception p0

    .line 132
    :try_start_4
    new-instance v0, Lum/n;

    .line 133
    .line 134
    invoke-direct {v0, p0}, Lum/n;-><init>(Ljava/lang/Throwable;)V

    .line 135
    .line 136
    .line 137
    goto :goto_2

    .line 138
    :cond_4
    sget-object v1, Lfn/a;->h:[Ljava/lang/String;

    .line 139
    .line 140
    new-instance v1, Lfn/b;

    .line 141
    .line 142
    invoke-direct {v1, v0}, Lfn/b;-><init>(Lu01/b0;)V

    .line 143
    .line 144
    .line 145
    invoke-static {v1, p0, v2}, Lum/d;->a(Lfn/b;Ljava/lang/String;Z)Lum/n;

    .line 146
    .line 147
    .line 148
    move-result-object p0
    :try_end_4
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_4 .. :try_end_4} :catch_1

    .line 149
    return-object p0

    .line 150
    :catch_1
    move-exception p0

    .line 151
    new-instance v0, Lum/n;

    .line 152
    .line 153
    invoke-direct {v0, p0}, Lum/n;-><init>(Ljava/lang/Throwable;)V

    .line 154
    .line 155
    .line 156
    :goto_2
    return-object v0
.end method
