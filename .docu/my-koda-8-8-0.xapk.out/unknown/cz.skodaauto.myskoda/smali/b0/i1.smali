.class public final Lb0/i1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lh0/o1;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    sget-object v0, Ls0/c;->c:Ls0/c;

    .line 2
    .line 3
    new-instance v1, Ls0/b;

    .line 4
    .line 5
    sget-object v2, Ls0/a;->a:Ls0/a;

    .line 6
    .line 7
    invoke-direct {v1, v2, v0}, Ls0/b;-><init>(Ls0/a;Ls0/c;)V

    .line 8
    .line 9
    .line 10
    new-instance v0, Lb0/h1;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-direct {v0, v2}, Lb0/h1;-><init>(I)V

    .line 14
    .line 15
    .line 16
    sget-object v2, Lh0/o2;->T0:Lh0/g;

    .line 17
    .line 18
    const/4 v3, 0x2

    .line 19
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    iget-object v0, v0, Lb0/h1;->b:Lh0/j1;

    .line 24
    .line 25
    invoke-virtual {v0, v2, v3}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    sget-object v2, Lh0/a1;->F0:Lh0/g;

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    invoke-virtual {v0, v2, v3}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    sget-object v2, Lh0/a1;->N0:Lh0/g;

    .line 39
    .line 40
    invoke-virtual {v0, v2, v1}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    sget-object v1, Lh0/o2;->Y0:Lh0/g;

    .line 44
    .line 45
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 46
    .line 47
    invoke-virtual {v0, v1, v2}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    sget-object v1, Lh0/z0;->E0:Lh0/g;

    .line 51
    .line 52
    sget-object v2, Lb0/y;->c:Lb0/y;

    .line 53
    .line 54
    invoke-virtual {v0, v1, v2}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    new-instance v1, Lh0/o1;

    .line 58
    .line 59
    invoke-static {v0}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    invoke-direct {v1, v0}, Lh0/o1;-><init>(Lh0/n1;)V

    .line 64
    .line 65
    .line 66
    sput-object v1, Lb0/i1;->a:Lh0/o1;

    .line 67
    .line 68
    return-void
.end method
