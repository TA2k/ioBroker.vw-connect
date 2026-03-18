.class public final Lh70/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lij0/a;


# direct methods
.method public constructor <init>(Lij0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh70/o;->a:Lij0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Lh70/o;->a:Lij0/a;

    .line 2
    .line 3
    const-string v1, "id"

    .line 4
    .line 5
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v1, "rpaplugin_"

    .line 9
    .line 10
    invoke-virtual {v1, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    :try_start_0
    move-object v2, v0

    .line 15
    check-cast v2, Ljj0/f;

    .line 16
    .line 17
    const-string v3, "name"

    .line 18
    .line 19
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object v2, v2, Ljj0/f;->a:Landroid/content/Context;

    .line 23
    .line 24
    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    const-string v4, "string"

    .line 29
    .line 30
    invoke-virtual {v2}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    invoke-virtual {v3, v1, v4, v2}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    const/4 v3, 0x0

    .line 39
    new-array v3, v3, [Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Ljj0/f;

    .line 42
    .line 43
    invoke-virtual {v0, v2, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0
    :try_end_0
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 47
    return-object p0

    .line 48
    :catch_0
    new-instance v0, Lh70/n;

    .line 49
    .line 50
    const/4 v2, 0x0

    .line 51
    invoke-direct {v0, p1, v1, v2}, Lh70/n;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    .line 52
    .line 53
    .line 54
    const/4 p1, 0x0

    .line 55
    invoke-static {p1, p0, v0}, Llp/nd;->m(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 56
    .line 57
    .line 58
    return-object v1
.end method
