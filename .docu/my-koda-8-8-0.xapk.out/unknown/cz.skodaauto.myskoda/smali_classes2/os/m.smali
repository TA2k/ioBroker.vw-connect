.class public final Los/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Los/d;


# static fields
.field public static final f:Ljava/nio/charset/Charset;


# instance fields
.field public final d:Ljava/io/File;

.field public e:Los/l;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "UTF-8"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/nio/charset/Charset;->forName(Ljava/lang/String;)Ljava/nio/charset/Charset;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Los/m;->f:Ljava/nio/charset/Charset;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Ljava/io/File;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Los/m;->d:Ljava/io/File;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    iget-object v0, p0, Los/m;->e:Los/l;

    .line 2
    .line 3
    const-string v1, "There was a problem closing the Crashlytics log file."

    .line 4
    .line 5
    invoke-static {v0, v1}, Lms/f;->b(Ljava/io/Closeable;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    iput-object v0, p0, Los/m;->e:Los/l;

    .line 10
    .line 11
    return-void
.end method

.method public final b()V
    .locals 3

    .line 1
    iget-object v0, p0, Los/m;->d:Ljava/io/File;

    .line 2
    .line 3
    iget-object v1, p0, Los/m;->e:Los/l;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    :try_start_0
    new-instance v1, Los/l;

    .line 8
    .line 9
    invoke-direct {v1, v0}, Los/l;-><init>(Ljava/io/File;)V

    .line 10
    .line 11
    .line 12
    iput-object v1, p0, Los/m;->e:Los/l;
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    .line 14
    return-void

    .line 15
    :catch_0
    move-exception p0

    .line 16
    new-instance v1, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v2, "Could not open log file: "

    .line 19
    .line 20
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    const-string v1, "FirebaseCrashlytics"

    .line 31
    .line 32
    invoke-static {v1, v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 33
    .line 34
    .line 35
    :cond_0
    return-void
.end method

.method public final c()Ljava/lang/String;
    .locals 6

    .line 1
    iget-object v0, p0, Los/m;->d:Ljava/io/File;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    :goto_0
    move-object p0, v2

    .line 12
    goto :goto_2

    .line 13
    :cond_0
    invoke-virtual {p0}, Los/m;->b()V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Los/m;->e:Los/l;

    .line 17
    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_1
    filled-new-array {v1}, [I

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    invoke-virtual {v0}, Los/l;->l()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    new-array v0, v0, [B

    .line 30
    .line 31
    :try_start_0
    iget-object p0, p0, Los/m;->e:Los/l;

    .line 32
    .line 33
    new-instance v4, Los/f;

    .line 34
    .line 35
    invoke-direct {v4, v0, v3}, Los/f;-><init>([B[I)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0, v4}, Los/l;->d(Los/k;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :catch_0
    move-exception p0

    .line 43
    const-string v4, "A problem occurred while reading the Crashlytics log file."

    .line 44
    .line 45
    const-string v5, "FirebaseCrashlytics"

    .line 46
    .line 47
    invoke-static {v5, v4, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 48
    .line 49
    .line 50
    :goto_1
    new-instance p0, Lb11/a;

    .line 51
    .line 52
    aget v3, v3, v1

    .line 53
    .line 54
    const/4 v4, 0x7

    .line 55
    invoke-direct {p0, v0, v3, v4}, Lb11/a;-><init>(Ljava/lang/Object;II)V

    .line 56
    .line 57
    .line 58
    :goto_2
    if-nez p0, :cond_2

    .line 59
    .line 60
    move-object v3, v2

    .line 61
    goto :goto_3

    .line 62
    :cond_2
    iget v0, p0, Lb11/a;->e:I

    .line 63
    .line 64
    new-array v3, v0, [B

    .line 65
    .line 66
    iget-object p0, p0, Lb11/a;->f:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p0, [B

    .line 69
    .line 70
    invoke-static {p0, v1, v3, v1, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 71
    .line 72
    .line 73
    :goto_3
    if-eqz v3, :cond_3

    .line 74
    .line 75
    new-instance p0, Ljava/lang/String;

    .line 76
    .line 77
    sget-object v0, Los/m;->f:Ljava/nio/charset/Charset;

    .line 78
    .line 79
    invoke-direct {p0, v3, v0}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 80
    .line 81
    .line 82
    return-object p0

    .line 83
    :cond_3
    return-object v2
.end method

.method public final d(JLjava/lang/String;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Los/m;->b()V

    .line 2
    .line 3
    .line 4
    const-string v0, " "

    .line 5
    .line 6
    const-string v1, "..."

    .line 7
    .line 8
    iget-object v2, p0, Los/m;->e:Los/l;

    .line 9
    .line 10
    if-nez v2, :cond_0

    .line 11
    .line 12
    goto :goto_1

    .line 13
    :cond_0
    if-nez p3, :cond_1

    .line 14
    .line 15
    const-string p3, "null"

    .line 16
    .line 17
    :cond_1
    :try_start_0
    invoke-virtual {p3}, Ljava/lang/String;->length()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    const/16 v3, 0x4000

    .line 22
    .line 23
    if-le v2, v3, :cond_2

    .line 24
    .line 25
    new-instance v2, Ljava/lang/StringBuilder;

    .line 26
    .line 27
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p3}, Ljava/lang/String;->length()I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    sub-int/2addr v1, v3

    .line 35
    invoke-virtual {p3, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p3

    .line 39
    invoke-virtual {v2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p3

    .line 46
    :cond_2
    const-string v1, "\r"

    .line 47
    .line 48
    invoke-virtual {p3, v1, v0}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p3

    .line 52
    const-string v1, "\n"

    .line 53
    .line 54
    invoke-virtual {p3, v1, v0}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p3

    .line 58
    sget-object v0, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 59
    .line 60
    const-string v1, "%d %s%n"

    .line 61
    .line 62
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    filled-new-array {p1, p3}, [Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    invoke-static {v0, v1, p1}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    sget-object p2, Los/m;->f:Ljava/nio/charset/Charset;

    .line 75
    .line 76
    invoke-virtual {p1, p2}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    iget-object p2, p0, Los/m;->e:Los/l;

    .line 81
    .line 82
    invoke-virtual {p2, p1}, Los/l;->a([B)V

    .line 83
    .line 84
    .line 85
    :goto_0
    iget-object p1, p0, Los/m;->e:Los/l;

    .line 86
    .line 87
    invoke-virtual {p1}, Los/l;->f()Z

    .line 88
    .line 89
    .line 90
    move-result p1

    .line 91
    if-nez p1, :cond_3

    .line 92
    .line 93
    iget-object p1, p0, Los/m;->e:Los/l;

    .line 94
    .line 95
    invoke-virtual {p1}, Los/l;->l()I

    .line 96
    .line 97
    .line 98
    move-result p1

    .line 99
    const/high16 p2, 0x10000

    .line 100
    .line 101
    if-le p1, p2, :cond_3

    .line 102
    .line 103
    iget-object p1, p0, Los/m;->e:Los/l;

    .line 104
    .line 105
    invoke-virtual {p1}, Los/l;->remove()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 106
    .line 107
    .line 108
    goto :goto_0

    .line 109
    :cond_3
    :goto_1
    return-void

    .line 110
    :catch_0
    move-exception p0

    .line 111
    const-string p1, "There was a problem writing to the Crashlytics log."

    .line 112
    .line 113
    const-string p2, "FirebaseCrashlytics"

    .line 114
    .line 115
    invoke-static {p2, p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 116
    .line 117
    .line 118
    return-void
.end method
