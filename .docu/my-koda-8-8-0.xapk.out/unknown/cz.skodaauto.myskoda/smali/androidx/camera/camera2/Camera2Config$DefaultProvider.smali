.class public final Landroidx/camera/camera2/Camera2Config$DefaultProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lb0/v;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public getCameraXConfig()Lb0/w;
    .locals 4

    .line 1
    new-instance p0, Ls/a;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ls/b;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    new-instance v1, Ls/c;

    .line 12
    .line 13
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    new-instance v2, La0/i;

    .line 17
    .line 18
    const/4 v3, 0x1

    .line 19
    invoke-direct {v2, v3}, La0/i;-><init>(I)V

    .line 20
    .line 21
    .line 22
    sget-object v3, Lb0/w;->e:Lh0/g;

    .line 23
    .line 24
    iget-object v2, v2, La0/i;->b:Lh0/j1;

    .line 25
    .line 26
    invoke-virtual {v2, v3, p0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    sget-object p0, Lb0/w;->f:Lh0/g;

    .line 30
    .line 31
    invoke-virtual {v2, p0, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    sget-object p0, Lb0/w;->g:Lh0/g;

    .line 35
    .line 36
    invoke-virtual {v2, p0, v1}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    sget-object p0, Lb0/w;->o:Lh0/g;

    .line 40
    .line 41
    const/4 v0, 0x0

    .line 42
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    invoke-virtual {v2, p0, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    sget-object p0, Lb0/w;->p:Lh0/g;

    .line 50
    .line 51
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 52
    .line 53
    invoke-virtual {v2, p0, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    new-instance p0, Lb0/w;

    .line 57
    .line 58
    invoke-static {v2}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    invoke-direct {p0, v0}, Lb0/w;-><init>(Lh0/n1;)V

    .line 63
    .line 64
    .line 65
    return-object p0
.end method
