.class final Lretrofit2/RequestBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lretrofit2/RequestBuilder$ContentTypeOverridingRequestBody;
    }
.end annotation


# static fields
.field public static final l:[C

.field public static final m:Ljava/util/regex/Pattern;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ld01/a0;

.field public c:Ljava/lang/String;

.field public d:Ld01/z;

.field public final e:Ld01/j0;

.field public final f:Ld01/x;

.field public g:Ld01/d0;

.field public final h:Z

.field public final i:Lgw0/c;

.field public final j:Lb81/a;

.field public k:Ld01/r0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    new-array v0, v0, [C

    .line 4
    .line 5
    fill-array-data v0, :array_0

    .line 6
    .line 7
    .line 8
    sput-object v0, Lretrofit2/RequestBuilder;->l:[C

    .line 9
    .line 10
    const-string v0, "(.*/)?(\\.|%2e|%2E){1,2}(/.*)?"

    .line 11
    .line 12
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    sput-object v0, Lretrofit2/RequestBuilder;->m:Ljava/util/regex/Pattern;

    .line 17
    .line 18
    return-void

    .line 19
    :array_0
    .array-data 2
        0x30s
        0x31s
        0x32s
        0x33s
        0x34s
        0x35s
        0x36s
        0x37s
        0x38s
        0x39s
        0x41s
        0x42s
        0x43s
        0x44s
        0x45s
        0x46s
    .end array-data
.end method

.method public constructor <init>(Ljava/lang/String;Ld01/a0;Ljava/lang/String;Ld01/y;Ld01/d0;ZZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/RequestBuilder;->a:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lretrofit2/RequestBuilder;->b:Ld01/a0;

    .line 7
    .line 8
    iput-object p3, p0, Lretrofit2/RequestBuilder;->c:Ljava/lang/String;

    .line 9
    .line 10
    new-instance p1, Ld01/j0;

    .line 11
    .line 12
    invoke-direct {p1}, Ld01/j0;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lretrofit2/RequestBuilder;->e:Ld01/j0;

    .line 16
    .line 17
    iput-object p5, p0, Lretrofit2/RequestBuilder;->g:Ld01/d0;

    .line 18
    .line 19
    iput-boolean p6, p0, Lretrofit2/RequestBuilder;->h:Z

    .line 20
    .line 21
    if-eqz p4, :cond_0

    .line 22
    .line 23
    invoke-virtual {p4}, Ld01/y;->g()Ld01/x;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    iput-object p1, p0, Lretrofit2/RequestBuilder;->f:Ld01/x;

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    new-instance p1, Ld01/x;

    .line 31
    .line 32
    const/4 p2, 0x0

    .line 33
    const/4 p3, 0x0

    .line 34
    invoke-direct {p1, p3, p2}, Ld01/x;-><init>(BI)V

    .line 35
    .line 36
    .line 37
    iput-object p1, p0, Lretrofit2/RequestBuilder;->f:Ld01/x;

    .line 38
    .line 39
    :goto_0
    if-eqz p7, :cond_1

    .line 40
    .line 41
    new-instance p1, Lb81/a;

    .line 42
    .line 43
    const/4 p2, 0x3

    .line 44
    invoke-direct {p1, p2}, Lb81/a;-><init>(I)V

    .line 45
    .line 46
    .line 47
    iput-object p1, p0, Lretrofit2/RequestBuilder;->j:Lb81/a;

    .line 48
    .line 49
    return-void

    .line 50
    :cond_1
    if-eqz p8, :cond_3

    .line 51
    .line 52
    new-instance p1, Lgw0/c;

    .line 53
    .line 54
    const/16 p2, 0xc

    .line 55
    .line 56
    invoke-direct {p1, p2}, Lgw0/c;-><init>(I)V

    .line 57
    .line 58
    .line 59
    iput-object p1, p0, Lretrofit2/RequestBuilder;->i:Lgw0/c;

    .line 60
    .line 61
    sget-object p0, Ld01/f0;->f:Ld01/d0;

    .line 62
    .line 63
    const-string p2, "type"

    .line 64
    .line 65
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    iget-object p2, p0, Ld01/d0;->b:Ljava/lang/String;

    .line 69
    .line 70
    const-string p3, "multipart"

    .line 71
    .line 72
    invoke-virtual {p2, p3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result p2

    .line 76
    if-eqz p2, :cond_2

    .line 77
    .line 78
    iput-object p0, p1, Lgw0/c;->f:Ljava/lang/Object;

    .line 79
    .line 80
    return-void

    .line 81
    :cond_2
    new-instance p1, Ljava/lang/StringBuilder;

    .line 82
    .line 83
    const-string p2, "multipart != "

    .line 84
    .line 85
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 96
    .line 97
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    throw p1

    .line 105
    :cond_3
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Ljava/lang/String;Z)V
    .locals 10

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    iget-object p0, p0, Lretrofit2/RequestBuilder;->j:Lb81/a;

    .line 4
    .line 5
    if-eqz p3, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p3, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p3, Ljava/util/ArrayList;

    .line 16
    .line 17
    const/4 v7, 0x0

    .line 18
    const/16 v8, 0x53

    .line 19
    .line 20
    const/4 v1, 0x0

    .line 21
    const/4 v2, 0x0

    .line 22
    const-string v3, " !\"#$&\'()+,/:;<=>?@[\\]^`{|}~"

    .line 23
    .line 24
    const/4 v4, 0x1

    .line 25
    const/4 v5, 0x0

    .line 26
    const/4 v6, 0x1

    .line 27
    move-object v0, p1

    .line 28
    invoke-static/range {v0 .. v8}, Ls01/a;->b(Ljava/lang/String;IILjava/lang/String;ZZZZI)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    invoke-virtual {p3, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    iget-object p0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Ljava/util/ArrayList;

    .line 38
    .line 39
    const-string v3, " !\"#$&\'()+,/:;<=>?@[\\]^`{|}~"

    .line 40
    .line 41
    move-object v0, p2

    .line 42
    invoke-static/range {v0 .. v8}, Ls01/a;->b(Ljava/lang/String;IILjava/lang/String;ZZZZI)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_0
    move-object v9, v0

    .line 51
    move-object v0, p1

    .line 52
    move-object p1, p2

    .line 53
    move-object p2, v9

    .line 54
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 55
    .line 56
    .line 57
    invoke-static {v0, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    iget-object p2, p0, Lb81/a;->e:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast p2, Ljava/util/ArrayList;

    .line 63
    .line 64
    const/4 v7, 0x0

    .line 65
    const/16 v8, 0x5b

    .line 66
    .line 67
    const/4 v1, 0x0

    .line 68
    const/4 v2, 0x0

    .line 69
    const-string v3, " !\"#$&\'()+,/:;<=>?@[\\]^`{|}~"

    .line 70
    .line 71
    const/4 v4, 0x0

    .line 72
    const/4 v5, 0x0

    .line 73
    const/4 v6, 0x0

    .line 74
    invoke-static/range {v0 .. v8}, Ls01/a;->b(Ljava/lang/String;IILjava/lang/String;ZZZZI)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p3

    .line 78
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    iget-object p0, p0, Lb81/a;->f:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast p0, Ljava/util/ArrayList;

    .line 84
    .line 85
    const-string v3, " !\"#$&\'()+,/:;<=>?@[\\]^`{|}~"

    .line 86
    .line 87
    move-object v0, p1

    .line 88
    invoke-static/range {v0 .. v8}, Ls01/a;->b(Ljava/lang/String;IILjava/lang/String;ZZZZI)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    return-void
.end method

.method public final b(Ljava/lang/String;Ljava/lang/String;Z)V
    .locals 1

    .line 1
    const-string v0, "Content-Type"

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    :try_start_0
    sget-object p1, Ld01/d0;->e:Lly0/n;

    .line 10
    .line 11
    invoke-static {p2}, Ljp/ue;->c(Ljava/lang/String;)Ld01/d0;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iput-object p1, p0, Lretrofit2/RequestBuilder;->g:Ld01/d0;
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    .line 17
    return-void

    .line 18
    :catch_0
    move-exception p0

    .line 19
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 20
    .line 21
    const-string p3, "Malformed content type: "

    .line 22
    .line 23
    invoke-static {p3, p2}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    invoke-direct {p1, p2, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 28
    .line 29
    .line 30
    throw p1

    .line 31
    :cond_0
    iget-object p0, p0, Lretrofit2/RequestBuilder;->f:Ld01/x;

    .line 32
    .line 33
    if-eqz p3, :cond_1

    .line 34
    .line 35
    invoke-virtual {p0, p1, p2}, Ld01/x;->h(Ljava/lang/String;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_1
    invoke-virtual {p0, p1, p2}, Ld01/x;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    return-void
.end method

.method public final c(Ld01/y;Ld01/r0;)V
    .locals 2

    .line 1
    iget-object p0, p0, Lretrofit2/RequestBuilder;->i:Lgw0/c;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const-string v0, "body"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    const-string v1, "Content-Type"

    .line 15
    .line 16
    invoke-virtual {p1, v1}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move-object v1, v0

    .line 22
    :goto_0
    if-nez v1, :cond_3

    .line 23
    .line 24
    if-eqz p1, :cond_1

    .line 25
    .line 26
    const-string v0, "Content-Length"

    .line 27
    .line 28
    invoke-virtual {p1, v0}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    :cond_1
    if-nez v0, :cond_2

    .line 33
    .line 34
    new-instance v0, Ld01/e0;

    .line 35
    .line 36
    invoke-direct {v0, p1, p2}, Ld01/e0;-><init>(Ld01/y;Ld01/r0;)V

    .line 37
    .line 38
    .line 39
    iget-object p0, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p0, Ljava/util/ArrayList;

    .line 42
    .line 43
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 48
    .line 49
    const-string p1, "Unexpected header: Content-Length"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 56
    .line 57
    const-string p1, "Unexpected header: Content-Type"

    .line 58
    .line 59
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0
.end method

.method public final d(Ljava/lang/String;Ljava/lang/String;Z)V
    .locals 8

    .line 1
    iget-object v0, p0, Lretrofit2/RequestBuilder;->c:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_1

    .line 5
    .line 6
    iget-object v2, p0, Lretrofit2/RequestBuilder;->b:Ld01/a0;

    .line 7
    .line 8
    invoke-virtual {v2, v0}, Ld01/a0;->h(Ljava/lang/String;)Ld01/z;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Lretrofit2/RequestBuilder;->d:Ld01/z;

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    iput-object v1, p0, Lretrofit2/RequestBuilder;->c:Ljava/lang/String;

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 20
    .line 21
    new-instance p2, Ljava/lang/StringBuilder;

    .line 22
    .line 23
    const-string p3, "Malformed URL. Base: "

    .line 24
    .line 25
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p2, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string p3, ", Relative: "

    .line 32
    .line 33
    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lretrofit2/RequestBuilder;->c:Ljava/lang/String;

    .line 37
    .line 38
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p1

    .line 49
    :cond_1
    :goto_0
    if-eqz p3, :cond_4

    .line 50
    .line 51
    iget-object p0, p0, Lretrofit2/RequestBuilder;->d:Ld01/z;

    .line 52
    .line 53
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 54
    .line 55
    .line 56
    const-string p3, "encodedName"

    .line 57
    .line 58
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    iget-object p3, p0, Ld01/z;->i:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast p3, Ljava/util/ArrayList;

    .line 64
    .line 65
    if-nez p3, :cond_2

    .line 66
    .line 67
    new-instance p3, Ljava/util/ArrayList;

    .line 68
    .line 69
    invoke-direct {p3}, Ljava/util/ArrayList;-><init>()V

    .line 70
    .line 71
    .line 72
    iput-object p3, p0, Ld01/z;->i:Ljava/lang/Object;

    .line 73
    .line 74
    :cond_2
    iget-object p3, p0, Ld01/z;->i:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast p3, Ljava/util/ArrayList;

    .line 77
    .line 78
    invoke-static {p3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    const/4 v7, 0x1

    .line 82
    const/16 v4, 0x53

    .line 83
    .line 84
    const/4 v2, 0x0

    .line 85
    const/4 v3, 0x0

    .line 86
    const-string v6, " \"\'<>#&="

    .line 87
    .line 88
    move-object v5, p1

    .line 89
    invoke-static/range {v2 .. v7}, Ls01/a;->a(IIILjava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    invoke-interface {p3, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    iget-object p0, p0, Ld01/z;->i:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast p0, Ljava/util/ArrayList;

    .line 99
    .line 100
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    if-eqz p2, :cond_3

    .line 104
    .line 105
    const/4 v7, 0x1

    .line 106
    const/16 v4, 0x53

    .line 107
    .line 108
    const/4 v2, 0x0

    .line 109
    const/4 v3, 0x0

    .line 110
    const-string v6, " \"\'<>#&="

    .line 111
    .line 112
    move-object v5, p2

    .line 113
    invoke-static/range {v2 .. v7}, Ls01/a;->a(IIILjava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    :cond_3
    invoke-interface {p0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    return-void

    .line 121
    :cond_4
    move-object v5, p1

    .line 122
    move-object p1, p2

    .line 123
    iget-object p0, p0, Lretrofit2/RequestBuilder;->d:Ld01/z;

    .line 124
    .line 125
    invoke-virtual {p0, v5, p1}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    return-void
.end method
