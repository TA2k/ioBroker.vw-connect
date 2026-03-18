.class public final Lb0/r0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lh0/y0;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    sget-object v0, Lh0/c2;->h:Lh0/c2;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    sget-object v2, Ls0/c;->c:Ls0/c;

    .line 9
    .line 10
    new-instance v3, Ls0/b;

    .line 11
    .line 12
    sget-object v4, Ls0/a;->a:Ls0/a;

    .line 13
    .line 14
    invoke-direct {v3, v4, v2}, Ls0/b;-><init>(Ls0/a;Ls0/c;)V

    .line 15
    .line 16
    .line 17
    new-instance v2, Lb0/f0;

    .line 18
    .line 19
    const/4 v4, 0x1

    .line 20
    invoke-direct {v2, v4}, Lb0/f0;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sget-object v4, Lh0/o2;->T0:Lh0/g;

    .line 24
    .line 25
    const/4 v5, 0x4

    .line 26
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 27
    .line 28
    .line 29
    move-result-object v5

    .line 30
    iget-object v2, v2, Lb0/f0;->b:Lh0/j1;

    .line 31
    .line 32
    invoke-virtual {v2, v4, v5}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    sget-object v4, Lh0/o2;->d1:Lh0/g;

    .line 36
    .line 37
    invoke-virtual {v2, v4, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    sget-object v0, Lh0/a1;->F0:Lh0/g;

    .line 41
    .line 42
    invoke-virtual {v2, v0, v1}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    sget-object v0, Lh0/a1;->N0:Lh0/g;

    .line 46
    .line 47
    invoke-virtual {v2, v0, v3}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    sget-object v0, Lh0/y0;->h:Lh0/g;

    .line 51
    .line 52
    invoke-virtual {v2, v0, v1}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    sget-object v0, Lh0/z0;->E0:Lh0/g;

    .line 56
    .line 57
    sget-object v1, Lb0/y;->d:Lb0/y;

    .line 58
    .line 59
    invoke-virtual {v2, v0, v1}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    new-instance v0, Lh0/y0;

    .line 63
    .line 64
    invoke-static {v2}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    invoke-direct {v0, v1}, Lh0/y0;-><init>(Lh0/n1;)V

    .line 69
    .line 70
    .line 71
    sput-object v0, Lb0/r0;->a:Lh0/y0;

    .line 72
    .line 73
    return-void
.end method
