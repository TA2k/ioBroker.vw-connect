.class public abstract Lmm/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ld8/c;

.field public static final b:Ld8/c;

.field public static final c:Ld8/c;

.field public static final d:Ld8/c;

.field public static final e:Ld8/c;

.field public static final f:Ld8/c;

.field public static final g:Ld8/c;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ld8/c;

    .line 2
    .line 3
    sget-object v1, Lrm/e;->a:Lrm/c;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ld8/c;-><init>(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lmm/i;->a:Ld8/c;

    .line 9
    .line 10
    new-instance v0, Ld8/c;

    .line 11
    .line 12
    sget-object v1, Lsm/i;->b:Landroid/graphics/Bitmap$Config;

    .line 13
    .line 14
    invoke-direct {v0, v1}, Ld8/c;-><init>(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lmm/i;->b:Ld8/c;

    .line 18
    .line 19
    new-instance v0, Ld8/c;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, v1}, Ld8/c;-><init>(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    sput-object v0, Lmm/i;->c:Ld8/c;

    .line 26
    .line 27
    new-instance v0, Ld8/c;

    .line 28
    .line 29
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 30
    .line 31
    invoke-direct {v0, v2}, Ld8/c;-><init>(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    sput-object v0, Lmm/i;->d:Ld8/c;

    .line 35
    .line 36
    new-instance v0, Ld8/c;

    .line 37
    .line 38
    invoke-direct {v0, v1}, Ld8/c;-><init>(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    sput-object v0, Lmm/i;->e:Ld8/c;

    .line 42
    .line 43
    new-instance v0, Ld8/c;

    .line 44
    .line 45
    invoke-direct {v0, v2}, Ld8/c;-><init>(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    sput-object v0, Lmm/i;->f:Ld8/c;

    .line 49
    .line 50
    new-instance v0, Ld8/c;

    .line 51
    .line 52
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 53
    .line 54
    invoke-direct {v0, v1}, Ld8/c;-><init>(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    sput-object v0, Lmm/i;->g:Ld8/c;

    .line 58
    .line 59
    return-void
.end method

.method public static final a(Lmm/n;)Landroid/graphics/Bitmap$Config;
    .locals 1

    .line 1
    sget-object v0, Lmm/i;->b:Ld8/c;

    .line 2
    .line 3
    invoke-static {p0, v0}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Landroid/graphics/Bitmap$Config;

    .line 8
    .line 9
    return-object p0
.end method
