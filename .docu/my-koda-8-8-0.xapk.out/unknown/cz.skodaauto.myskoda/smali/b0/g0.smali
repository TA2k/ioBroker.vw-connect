.class public final Lb0/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lh0/x0;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Landroid/util/Size;

    .line 2
    .line 3
    const/16 v1, 0x280

    .line 4
    .line 5
    const/16 v2, 0x1e0

    .line 6
    .line 7
    invoke-direct {v0, v1, v2}, Landroid/util/Size;-><init>(II)V

    .line 8
    .line 9
    .line 10
    new-instance v1, Ls0/c;

    .line 11
    .line 12
    sget-object v2, Lo0/a;->b:Landroid/util/Size;

    .line 13
    .line 14
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object v2, v1, Ls0/c;->a:Landroid/util/Size;

    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    iput v2, v1, Ls0/c;->b:I

    .line 21
    .line 22
    new-instance v3, Ls0/b;

    .line 23
    .line 24
    sget-object v4, Ls0/a;->a:Ls0/a;

    .line 25
    .line 26
    invoke-direct {v3, v4, v1}, Ls0/b;-><init>(Ls0/a;Ls0/c;)V

    .line 27
    .line 28
    .line 29
    new-instance v1, Lb0/f0;

    .line 30
    .line 31
    const/4 v4, 0x0

    .line 32
    invoke-direct {v1, v4}, Lb0/f0;-><init>(I)V

    .line 33
    .line 34
    .line 35
    sget-object v4, Lh0/a1;->K0:Lh0/g;

    .line 36
    .line 37
    iget-object v1, v1, Lb0/f0;->b:Lh0/j1;

    .line 38
    .line 39
    invoke-virtual {v1, v4, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    sget-object v0, Lh0/o2;->T0:Lh0/g;

    .line 43
    .line 44
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    invoke-virtual {v1, v0, v2}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    sget-object v0, Lh0/a1;->F0:Lh0/g;

    .line 52
    .line 53
    const/4 v2, 0x0

    .line 54
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    invoke-virtual {v1, v0, v2}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    sget-object v0, Lh0/a1;->N0:Lh0/g;

    .line 62
    .line 63
    invoke-virtual {v1, v0, v3}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    sget-object v0, Lb0/y;->d:Lb0/y;

    .line 67
    .line 68
    invoke-virtual {v0, v0}, Lb0/y;->equals(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    if-eqz v2, :cond_0

    .line 73
    .line 74
    sget-object v2, Lh0/z0;->E0:Lh0/g;

    .line 75
    .line 76
    invoke-virtual {v1, v2, v0}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    new-instance v0, Lh0/x0;

    .line 80
    .line 81
    invoke-static {v1}, Lh0/n1;->a(Lh0/q0;)Lh0/n1;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    invoke-direct {v0, v1}, Lh0/x0;-><init>(Lh0/n1;)V

    .line 86
    .line 87
    .line 88
    sput-object v0, Lb0/g0;->a:Lh0/x0;

    .line 89
    .line 90
    return-void

    .line 91
    :cond_0
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 92
    .line 93
    const-string v1, "ImageAnalysis currently only supports SDR"

    .line 94
    .line 95
    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    throw v0
.end method
