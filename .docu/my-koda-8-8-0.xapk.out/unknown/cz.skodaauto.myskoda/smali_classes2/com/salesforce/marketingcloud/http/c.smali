.class public final Lcom/salesforce/marketingcloud/http/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/http/g;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/http/c$a;,
        Lcom/salesforce/marketingcloud/http/c$b;,
        Lcom/salesforce/marketingcloud/http/c$c;
    }
.end annotation


# static fields
.field public static final j:Lcom/salesforce/marketingcloud/http/c$b;

.field private static final k:Ljava/lang/String;

.field public static final l:Ljava/lang/String; = "GET"

.field public static final m:Ljava/lang/String; = "POST"

.field public static final n:Ljava/lang/String; = "PATCH"

.field public static final o:I = -0x64

.field private static final p:I = 0x7530


# instance fields
.field private final b:Ljava/lang/String;

.field private final c:Ljava/lang/String;

.field private final d:I

.field private final e:Ljava/lang/String;

.field private final f:Ljava/lang/String;

.field private final g:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final h:Lcom/salesforce/marketingcloud/http/b;

.field private i:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/http/c$b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/http/c$b;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/http/c;->j:Lcom/salesforce/marketingcloud/http/c$b;

    .line 8
    .line 9
    const-string v0, "Request"

    .line 10
    .line 11
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lcom/salesforce/marketingcloud/http/c;->k:Ljava/lang/String;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/util/List;Lcom/salesforce/marketingcloud/http/b;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "I",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Lcom/salesforce/marketingcloud/http/b;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "method"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "contentType"

    .line 7
    .line 8
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "url"

    .line 12
    .line 13
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "headers"

    .line 17
    .line 18
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "requestId"

    .line 22
    .line 23
    invoke-static {p7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Lcom/salesforce/marketingcloud/http/c;->b:Ljava/lang/String;

    .line 30
    .line 31
    iput-object p2, p0, Lcom/salesforce/marketingcloud/http/c;->c:Ljava/lang/String;

    .line 32
    .line 33
    iput p3, p0, Lcom/salesforce/marketingcloud/http/c;->d:I

    .line 34
    .line 35
    iput-object p4, p0, Lcom/salesforce/marketingcloud/http/c;->e:Ljava/lang/String;

    .line 36
    .line 37
    iput-object p5, p0, Lcom/salesforce/marketingcloud/http/c;->f:Ljava/lang/String;

    .line 38
    .line 39
    iput-object p6, p0, Lcom/salesforce/marketingcloud/http/c;->g:Ljava/util/List;

    .line 40
    .line 41
    iput-object p7, p0, Lcom/salesforce/marketingcloud/http/c;->h:Lcom/salesforce/marketingcloud/http/b;

    .line 42
    .line 43
    return-void
.end method

.method public static final a(Landroid/os/Bundle;)Lcom/salesforce/marketingcloud/http/c;
    .locals 1

    .line 3
    sget-object v0, Lcom/salesforce/marketingcloud/http/c;->j:Lcom/salesforce/marketingcloud/http/c$b;

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/http/c$b;->a(Landroid/os/Bundle;)Lcom/salesforce/marketingcloud/http/c;

    move-result-object p0

    return-object p0
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/http/c;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/util/List;Lcom/salesforce/marketingcloud/http/b;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/http/c;
    .locals 0

    and-int/lit8 p9, p8, 0x1

    if-eqz p9, :cond_0

    .line 2
    iget-object p1, p0, Lcom/salesforce/marketingcloud/http/c;->b:Ljava/lang/String;

    :cond_0
    and-int/lit8 p9, p8, 0x2

    if-eqz p9, :cond_1

    iget-object p2, p0, Lcom/salesforce/marketingcloud/http/c;->c:Ljava/lang/String;

    :cond_1
    and-int/lit8 p9, p8, 0x4

    if-eqz p9, :cond_2

    iget p3, p0, Lcom/salesforce/marketingcloud/http/c;->d:I

    :cond_2
    and-int/lit8 p9, p8, 0x8

    if-eqz p9, :cond_3

    iget-object p4, p0, Lcom/salesforce/marketingcloud/http/c;->e:Ljava/lang/String;

    :cond_3
    and-int/lit8 p9, p8, 0x10

    if-eqz p9, :cond_4

    iget-object p5, p0, Lcom/salesforce/marketingcloud/http/c;->f:Ljava/lang/String;

    :cond_4
    and-int/lit8 p9, p8, 0x20

    if-eqz p9, :cond_5

    iget-object p6, p0, Lcom/salesforce/marketingcloud/http/c;->g:Ljava/util/List;

    :cond_5
    and-int/lit8 p8, p8, 0x40

    if-eqz p8, :cond_6

    iget-object p7, p0, Lcom/salesforce/marketingcloud/http/c;->h:Lcom/salesforce/marketingcloud/http/b;

    :cond_6
    move-object p8, p6

    move-object p9, p7

    move-object p6, p4

    move-object p7, p5

    move-object p4, p2

    move p5, p3

    move-object p2, p0

    move-object p3, p1

    invoke-virtual/range {p2 .. p9}, Lcom/salesforce/marketingcloud/http/c;->a(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/util/List;Lcom/salesforce/marketingcloud/http/b;)Lcom/salesforce/marketingcloud/http/c;

    move-result-object p0

    return-object p0
.end method

.method public static final synthetic a()Ljava/lang/String;
    .locals 1

    .line 4
    sget-object v0, Lcom/salesforce/marketingcloud/http/c;->k:Ljava/lang/String;

    return-object v0
.end method

.method private final a(Ljava/io/InputStream;)Ljava/lang/String;
    .locals 2

    if-eqz p1, :cond_1

    .line 6
    new-instance p0, Ljava/io/BufferedReader;

    new-instance v0, Ljava/io/InputStreamReader;

    invoke-static {}, Lcom/salesforce/marketingcloud/internal/o;->b()Ljava/nio/charset/Charset;

    move-result-object v1

    invoke-direct {v0, p1, v1}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;Ljava/nio/charset/Charset;)V

    invoke-direct {p0, v0}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    .line 7
    :try_start_0
    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    .line 8
    invoke-virtual {p0}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v0

    :goto_0
    if-eqz v0, :cond_0

    .line 9
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v0, 0xa

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 10
    invoke-virtual {p0}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v0

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    .line 11
    :cond_0
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    invoke-virtual {p0}, Ljava/io/BufferedReader;->close()V

    return-object p1

    .line 13
    :goto_1
    :try_start_1
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-exception v0

    invoke-static {p0, p1}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw v0

    :cond_1
    const/4 p0, 0x0

    return-object p0
.end method

.method public static final b()Lcom/salesforce/marketingcloud/http/c$a;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/http/c;->j:Lcom/salesforce/marketingcloud/http/c$b;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/http/c$b;->a()Lcom/salesforce/marketingcloud/http/c$a;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    return-object v0
.end method


# virtual methods
.method public final a(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/util/List;Lcom/salesforce/marketingcloud/http/b;)Lcom/salesforce/marketingcloud/http/c;
    .locals 8
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "I",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Lcom/salesforce/marketingcloud/http/b;",
            ")",
            "Lcom/salesforce/marketingcloud/http/c;"
        }
    .end annotation

    .line 1
    const-string p0, "method"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "contentType"

    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "url"

    invoke-static {p5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "headers"

    invoke-static {p6, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p0, "requestId"

    invoke-static {p7, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Lcom/salesforce/marketingcloud/http/c;

    move-object v1, p1

    move-object v2, p2

    move v3, p3

    move-object v4, p4

    move-object v5, p5

    move-object v6, p6

    move-object v7, p7

    invoke-direct/range {v0 .. v7}, Lcom/salesforce/marketingcloud/http/c;-><init>(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/util/List;Lcom/salesforce/marketingcloud/http/b;)V

    return-object v0
.end method

.method public final a(Ljava/lang/String;)V
    .locals 0

    .line 5
    iput-object p1, p0, Lcom/salesforce/marketingcloud/http/c;->i:Ljava/lang/String;

    return-void
.end method

.method public final c()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/c;->b:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/c;->c:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final e()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/http/c;->d:I

    .line 2
    .line 3
    return p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcom/salesforce/marketingcloud/http/c;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lcom/salesforce/marketingcloud/http/c;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/c;->b:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/http/c;->b:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/c;->c:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcom/salesforce/marketingcloud/http/c;->c:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget v1, p0, Lcom/salesforce/marketingcloud/http/c;->d:I

    .line 36
    .line 37
    iget v3, p1, Lcom/salesforce/marketingcloud/http/c;->d:I

    .line 38
    .line 39
    if-eq v1, v3, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/c;->e:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v3, p1, Lcom/salesforce/marketingcloud/http/c;->e:Ljava/lang/String;

    .line 45
    .line 46
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/c;->f:Ljava/lang/String;

    .line 54
    .line 55
    iget-object v3, p1, Lcom/salesforce/marketingcloud/http/c;->f:Ljava/lang/String;

    .line 56
    .line 57
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-nez v1, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/c;->g:Ljava/util/List;

    .line 65
    .line 66
    iget-object v3, p1, Lcom/salesforce/marketingcloud/http/c;->g:Ljava/util/List;

    .line 67
    .line 68
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    if-nez v1, :cond_7

    .line 73
    .line 74
    return v2

    .line 75
    :cond_7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/c;->h:Lcom/salesforce/marketingcloud/http/b;

    .line 76
    .line 77
    iget-object p1, p1, Lcom/salesforce/marketingcloud/http/c;->h:Lcom/salesforce/marketingcloud/http/b;

    .line 78
    .line 79
    if-eq p0, p1, :cond_8

    .line 80
    .line 81
    return v2

    .line 82
    :cond_8
    return v0
.end method

.method public final f()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/c;->e:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final g()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/c;->f:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public h()Landroid/os/Bundle;
    .locals 3

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/c;->b:Ljava/lang/String;

    .line 7
    .line 8
    const-string v2, "method"

    .line 9
    .line 10
    invoke-virtual {v0, v2, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/c;->c:Ljava/lang/String;

    .line 14
    .line 15
    const-string v2, "requestBody"

    .line 16
    .line 17
    invoke-virtual {v0, v2, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    iget v1, p0, Lcom/salesforce/marketingcloud/http/c;->d:I

    .line 21
    .line 22
    const-string v2, "connectionTimeout"

    .line 23
    .line 24
    invoke-virtual {v0, v2, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/c;->e:Ljava/lang/String;

    .line 28
    .line 29
    const-string v2, "contentType"

    .line 30
    .line 31
    invoke-virtual {v0, v2, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/c;->f:Ljava/lang/String;

    .line 35
    .line 36
    const-string v2, "url"

    .line 37
    .line 38
    invoke-virtual {v0, v2, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/c;->g:Ljava/util/List;

    .line 42
    .line 43
    instance-of v2, v1, Ljava/util/ArrayList;

    .line 44
    .line 45
    if-eqz v2, :cond_0

    .line 46
    .line 47
    check-cast v1, Ljava/util/ArrayList;

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    new-instance v1, Ljava/util/ArrayList;

    .line 51
    .line 52
    iget-object v2, p0, Lcom/salesforce/marketingcloud/http/c;->g:Ljava/util/List;

    .line 53
    .line 54
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 55
    .line 56
    .line 57
    :goto_0
    const-string v2, "headers"

    .line 58
    .line 59
    invoke-virtual {v0, v2, v1}, Landroid/os/Bundle;->putStringArrayList(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 60
    .line 61
    .line 62
    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/c;->h:Lcom/salesforce/marketingcloud/http/b;

    .line 63
    .line 64
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    const-string v2, "mcRequestId"

    .line 69
    .line 70
    invoke-virtual {v0, v2, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 71
    .line 72
    .line 73
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/c;->i:Ljava/lang/String;

    .line 74
    .line 75
    const-string v1, "tag"

    .line 76
    .line 77
    invoke-virtual {v0, v1, p0}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    return-object v0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/http/c;->b:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Lcom/salesforce/marketingcloud/http/c;->c:Ljava/lang/String;

    .line 11
    .line 12
    if-nez v2, :cond_0

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    :goto_0
    add-int/2addr v0, v2

    .line 21
    mul-int/2addr v0, v1

    .line 22
    iget v2, p0, Lcom/salesforce/marketingcloud/http/c;->d:I

    .line 23
    .line 24
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lcom/salesforce/marketingcloud/http/c;->e:Ljava/lang/String;

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-object v2, p0, Lcom/salesforce/marketingcloud/http/c;->f:Ljava/lang/String;

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-object v2, p0, Lcom/salesforce/marketingcloud/http/c;->g:Ljava/util/List;

    .line 41
    .line 42
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/c;->h:Lcom/salesforce/marketingcloud/http/b;

    .line 47
    .line 48
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    add-int/2addr p0, v0

    .line 53
    return p0
.end method

.method public final i()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/c;->g:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final j()Lcom/salesforce/marketingcloud/http/b;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/c;->h:Lcom/salesforce/marketingcloud/http/b;

    .line 2
    .line 3
    return-object p0
.end method

.method public final k()Lcom/salesforce/marketingcloud/http/f;
    .locals 10

    .line 1
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const/4 v2, 0x0

    .line 6
    :try_start_0
    new-instance v3, Ljava/net/URL;

    .line 7
    .line 8
    iget-object v4, p0, Lcom/salesforce/marketingcloud/http/c;->f:Ljava/lang/String;

    .line 9
    .line 10
    invoke-direct {v3, v4}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v3}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    invoke-static {v3}, Lcom/google/firebase/perf/network/FirebasePerfUrlConnection;->instrument(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    check-cast v3, Ljava/net/URLConnection;

    .line 22
    .line 23
    const-string v4, "null cannot be cast to non-null type javax.net.ssl.HttpsURLConnection"

    .line 24
    .line 25
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    check-cast v3, Ljavax/net/ssl/HttpsURLConnection;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_2
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 29
    .line 30
    :try_start_1
    iget-object v2, p0, Lcom/salesforce/marketingcloud/http/c;->b:Ljava/lang/String;

    .line 31
    .line 32
    invoke-virtual {v3, v2}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    const/4 v2, 0x1

    .line 36
    invoke-virtual {v3, v2}, Ljava/net/URLConnection;->setDoInput(Z)V

    .line 37
    .line 38
    .line 39
    const/4 v4, 0x0

    .line 40
    invoke-virtual {v3, v4}, Ljava/net/URLConnection;->setUseCaches(Z)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v3, v4}, Ljava/net/URLConnection;->setAllowUserInteraction(Z)V

    .line 44
    .line 45
    .line 46
    iget v5, p0, Lcom/salesforce/marketingcloud/http/c;->d:I

    .line 47
    .line 48
    invoke-virtual {v3, v5}, Ljava/net/URLConnection;->setConnectTimeout(I)V

    .line 49
    .line 50
    .line 51
    iget-object v5, p0, Lcom/salesforce/marketingcloud/http/c;->g:Ljava/util/List;

    .line 52
    .line 53
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 54
    .line 55
    .line 56
    move-result v5

    .line 57
    invoke-static {v4, v5}, Lkp/r9;->m(II)Lgy0/j;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    const/4 v5, 0x2

    .line 62
    invoke-static {v5, v4}, Lkp/r9;->l(ILgy0/j;)Lgy0/h;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    iget v5, v4, Lgy0/h;->d:I

    .line 67
    .line 68
    iget v6, v4, Lgy0/h;->e:I

    .line 69
    .line 70
    iget v4, v4, Lgy0/h;->f:I

    .line 71
    .line 72
    if-lez v4, :cond_0

    .line 73
    .line 74
    if-le v5, v6, :cond_1

    .line 75
    .line 76
    :cond_0
    if-gez v4, :cond_2

    .line 77
    .line 78
    if-gt v6, v5, :cond_2

    .line 79
    .line 80
    :cond_1
    :goto_0
    iget-object v7, p0, Lcom/salesforce/marketingcloud/http/c;->g:Ljava/util/List;

    .line 81
    .line 82
    invoke-interface {v7, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v7

    .line 86
    check-cast v7, Ljava/lang/String;

    .line 87
    .line 88
    iget-object v8, p0, Lcom/salesforce/marketingcloud/http/c;->g:Ljava/util/List;

    .line 89
    .line 90
    add-int/lit8 v9, v5, 0x1

    .line 91
    .line 92
    invoke-interface {v8, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v8

    .line 96
    check-cast v8, Ljava/lang/String;

    .line 97
    .line 98
    invoke-virtual {v3, v7, v8}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    if-eq v5, v6, :cond_2

    .line 102
    .line 103
    add-int/2addr v5, v4

    .line 104
    goto :goto_0

    .line 105
    :catchall_0
    move-exception p0

    .line 106
    move-object v2, v3

    .line 107
    goto/16 :goto_5

    .line 108
    .line 109
    :catch_0
    move-exception p0

    .line 110
    move-object v2, v3

    .line 111
    goto/16 :goto_3

    .line 112
    .line 113
    :cond_2
    iget-object v4, p0, Lcom/salesforce/marketingcloud/http/c;->c:Ljava/lang/String;

    .line 114
    .line 115
    if-eqz v4, :cond_3

    .line 116
    .line 117
    invoke-virtual {v3, v2}, Ljava/net/URLConnection;->setDoOutput(Z)V

    .line 118
    .line 119
    .line 120
    const-string v2, "content-type"

    .line 121
    .line 122
    iget-object v5, p0, Lcom/salesforce/marketingcloud/http/c;->e:Ljava/lang/String;

    .line 123
    .line 124
    invoke-virtual {v3, v2, v5}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v3}, Ljava/net/URLConnection;->getOutputStream()Ljava/io/OutputStream;

    .line 128
    .line 129
    .line 130
    move-result-object v2
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 131
    :try_start_2
    invoke-static {}, Lcom/salesforce/marketingcloud/internal/o;->b()Ljava/nio/charset/Charset;

    .line 132
    .line 133
    .line 134
    move-result-object v5

    .line 135
    invoke-virtual {v4, v5}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 136
    .line 137
    .line 138
    move-result-object v4

    .line 139
    const-string v5, "getBytes(...)"

    .line 140
    .line 141
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v2, v4}, Ljava/io/OutputStream;->write([B)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 145
    .line 146
    .line 147
    :try_start_3
    invoke-interface {v2}, Ljava/io/Closeable;->close()V
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 148
    .line 149
    .line 150
    goto :goto_1

    .line 151
    :catchall_1
    move-exception p0

    .line 152
    :try_start_4
    throw p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 153
    :catchall_2
    move-exception v0

    .line 154
    :try_start_5
    invoke-static {v2, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 155
    .line 156
    .line 157
    throw v0

    .line 158
    :cond_3
    :goto_1
    sget-object v2, Lcom/salesforce/marketingcloud/http/f;->h:Lcom/salesforce/marketingcloud/http/f$b;

    .line 159
    .line 160
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/http/f$b;->a()Lcom/salesforce/marketingcloud/http/f$a;

    .line 161
    .line 162
    .line 163
    move-result-object v2

    .line 164
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->getResponseCode()I

    .line 165
    .line 166
    .line 167
    move-result v4

    .line 168
    invoke-virtual {v2, v4}, Lcom/salesforce/marketingcloud/http/f$a;->a(I)Lcom/salesforce/marketingcloud/http/f$a;

    .line 169
    .line 170
    .line 171
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->getResponseMessage()Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v4

    .line 175
    invoke-virtual {v2, v4}, Lcom/salesforce/marketingcloud/http/f$a;->b(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/f$a;

    .line 176
    .line 177
    .line 178
    invoke-virtual {v3}, Ljava/net/URLConnection;->getHeaderFields()Ljava/util/Map;

    .line 179
    .line 180
    .line 181
    move-result-object v4

    .line 182
    invoke-virtual {v2, v4}, Lcom/salesforce/marketingcloud/http/f$a;->a(Ljava/util/Map;)Lcom/salesforce/marketingcloud/http/f$a;
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 183
    .line 184
    .line 185
    :try_start_6
    invoke-virtual {v3}, Ljava/net/URLConnection;->getInputStream()Ljava/io/InputStream;

    .line 186
    .line 187
    .line 188
    move-result-object v4

    .line 189
    invoke-direct {p0, v4}, Lcom/salesforce/marketingcloud/http/c;->a(Ljava/io/InputStream;)Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v4

    .line 193
    if-eqz v4, :cond_4

    .line 194
    .line 195
    invoke-virtual {v2, v4}, Lcom/salesforce/marketingcloud/http/f$a;->a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/f$a;
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_1
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 196
    .line 197
    .line 198
    goto :goto_2

    .line 199
    :catch_1
    :try_start_7
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->getErrorStream()Ljava/io/InputStream;

    .line 200
    .line 201
    .line 202
    move-result-object v4

    .line 203
    invoke-direct {p0, v4}, Lcom/salesforce/marketingcloud/http/c;->a(Ljava/io/InputStream;)Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object p0

    .line 207
    if-eqz p0, :cond_4

    .line 208
    .line 209
    invoke-virtual {v2, p0}, Lcom/salesforce/marketingcloud/http/f$a;->a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/f$a;

    .line 210
    .line 211
    .line 212
    :cond_4
    :goto_2
    invoke-virtual {v2, v0, v1}, Lcom/salesforce/marketingcloud/http/f$a;->b(J)Lcom/salesforce/marketingcloud/http/f$a;

    .line 213
    .line 214
    .line 215
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 216
    .line 217
    .line 218
    move-result-wide v0

    .line 219
    invoke-virtual {v2, v0, v1}, Lcom/salesforce/marketingcloud/http/f$a;->a(J)Lcom/salesforce/marketingcloud/http/f$a;

    .line 220
    .line 221
    .line 222
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/http/f$a;->a()Lcom/salesforce/marketingcloud/http/f;

    .line 223
    .line 224
    .line 225
    move-result-object p0
    :try_end_7
    .catch Ljava/lang/Exception; {:try_start_7 .. :try_end_7} :catch_0
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 226
    invoke-virtual {v3}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 227
    .line 228
    .line 229
    goto :goto_4

    .line 230
    :catchall_3
    move-exception p0

    .line 231
    goto :goto_5

    .line 232
    :catch_2
    move-exception p0

    .line 233
    :goto_3
    :try_start_8
    sget-object v0, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    .line 234
    .line 235
    sget-object v1, Lcom/salesforce/marketingcloud/http/c;->k:Ljava/lang/String;

    .line 236
    .line 237
    sget-object v3, Lcom/salesforce/marketingcloud/http/c$d;->b:Lcom/salesforce/marketingcloud/http/c$d;

    .line 238
    .line 239
    invoke-virtual {v0, v1, p0, v3}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 240
    .line 241
    .line 242
    sget-object p0, Lcom/salesforce/marketingcloud/http/f;->h:Lcom/salesforce/marketingcloud/http/f$b;

    .line 243
    .line 244
    const-string v0, "ERROR"

    .line 245
    .line 246
    const/16 v1, -0x64

    .line 247
    .line 248
    invoke-virtual {p0, v0, v1}, Lcom/salesforce/marketingcloud/http/f$b;->a(Ljava/lang/String;I)Lcom/salesforce/marketingcloud/http/f;

    .line 249
    .line 250
    .line 251
    move-result-object p0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 252
    if-eqz v2, :cond_5

    .line 253
    .line 254
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 255
    .line 256
    .line 257
    :cond_5
    :goto_4
    return-object p0

    .line 258
    :goto_5
    if-eqz v2, :cond_6

    .line 259
    .line 260
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 261
    .line 262
    .line 263
    :cond_6
    throw p0
.end method

.method public final l()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/http/c;->d:I

    .line 2
    .line 3
    return p0
.end method

.method public final m()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/c;->e:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final n()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/c;->g:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final o()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/c;->b:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final p()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/c;->c:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final q()Lcom/salesforce/marketingcloud/http/b;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/c;->h:Lcom/salesforce/marketingcloud/http/b;

    .line 2
    .line 3
    return-object p0
.end method

.method public final r()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/c;->i:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final s()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/c;->f:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 9

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/http/c;->b:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/http/c;->c:Ljava/lang/String;

    .line 4
    .line 5
    iget v2, p0, Lcom/salesforce/marketingcloud/http/c;->d:I

    .line 6
    .line 7
    iget-object v3, p0, Lcom/salesforce/marketingcloud/http/c;->e:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lcom/salesforce/marketingcloud/http/c;->f:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v5, p0, Lcom/salesforce/marketingcloud/http/c;->g:Ljava/util/List;

    .line 12
    .line 13
    iget-object p0, p0, Lcom/salesforce/marketingcloud/http/c;->h:Lcom/salesforce/marketingcloud/http/b;

    .line 14
    .line 15
    const-string v6, ", requestBody="

    .line 16
    .line 17
    const-string v7, ", connectionTimeout="

    .line 18
    .line 19
    const-string v8, "Request(method="

    .line 20
    .line 21
    invoke-static {v8, v0, v6, v1, v7}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", contentType="

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    const-string v1, ", url="

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", headers="

    .line 42
    .line 43
    const-string v2, ", requestId="

    .line 44
    .line 45
    invoke-static {v0, v4, v1, v5, v2}, Lu/w;->m(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string p0, ")"

    .line 52
    .line 53
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0
.end method
