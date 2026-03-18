.class public abstract Li2/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:Lx2/s;

.field public static final d:Lx2/s;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    const/16 v0, 0xa

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Li2/b;->a:F

    .line 5
    .line 6
    sput v0, Li2/b;->b:F

    .line 7
    .line 8
    new-instance v1, Lel/a;

    .line 9
    .line 10
    const/16 v2, 0x16

    .line 11
    .line 12
    invoke-direct {v1, v2}, Lel/a;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 16
    .line 17
    invoke-static {v2, v1}, Landroidx/compose/ui/layout/a;->b(Lx2/s;Lay0/o;)Lx2/s;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    new-instance v3, Lhz0/t1;

    .line 22
    .line 23
    const/16 v4, 0x9

    .line 24
    .line 25
    invoke-direct {v3, v4}, Lhz0/t1;-><init>(I)V

    .line 26
    .line 27
    .line 28
    const/4 v4, 0x1

    .line 29
    invoke-static {v1, v4, v3}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    const/4 v3, 0x2

    .line 34
    const/4 v5, 0x0

    .line 35
    invoke-static {v1, v0, v5, v3}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    sput-object v1, Li2/b;->c:Lx2/s;

    .line 40
    .line 41
    new-instance v1, Lel/a;

    .line 42
    .line 43
    const/16 v3, 0x17

    .line 44
    .line 45
    invoke-direct {v1, v3}, Lel/a;-><init>(I)V

    .line 46
    .line 47
    .line 48
    invoke-static {v2, v1}, Landroidx/compose/ui/layout/a;->b(Lx2/s;Lay0/o;)Lx2/s;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    new-instance v2, Lhz0/t1;

    .line 53
    .line 54
    const/16 v3, 0x9

    .line 55
    .line 56
    invoke-direct {v2, v3}, Lhz0/t1;-><init>(I)V

    .line 57
    .line 58
    .line 59
    invoke-static {v1, v4, v2}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    invoke-static {v1, v5, v0, v4}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    sput-object v0, Li2/b;->d:Lx2/s;

    .line 68
    .line 69
    return-void
.end method
