.class public final Leq0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Lu2/l;

.field public static final e:F

.field public static final f:F


# instance fields
.field public final a:F

.field public final b:Ll2/j1;

.field public final c:Ll2/j1;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ldl0/k;

    .line 2
    .line 3
    const/16 v1, 0x17

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ldl0/k;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Leh/b;

    .line 9
    .line 10
    const/16 v2, 0xe

    .line 11
    .line 12
    invoke-direct {v1, v2}, Leh/b;-><init>(I)V

    .line 13
    .line 14
    .line 15
    new-instance v2, Lu2/l;

    .line 16
    .line 17
    invoke-direct {v2, v0, v1}, Lu2/l;-><init>(Lay0/n;Lay0/k;)V

    .line 18
    .line 19
    .line 20
    sput-object v2, Leq0/c;->d:Lu2/l;

    .line 21
    .line 22
    const/16 v0, 0x38

    .line 23
    .line 24
    int-to-float v0, v0

    .line 25
    sput v0, Leq0/c;->e:F

    .line 26
    .line 27
    const/16 v0, 0x70

    .line 28
    .line 29
    int-to-float v0, v0

    .line 30
    sput v0, Leq0/c;->f:F

    .line 31
    .line 32
    return-void
.end method

.method public constructor <init>(F)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Leq0/c;->a:F

    .line 5
    .line 6
    new-instance v0, Lt4/f;

    .line 7
    .line 8
    invoke-direct {v0, p1}, Lt4/f;-><init>(F)V

    .line 9
    .line 10
    .line 11
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Leq0/c;->b:Ll2/j1;

    .line 16
    .line 17
    new-instance v0, Lt4/f;

    .line 18
    .line 19
    invoke-direct {v0, p1}, Lt4/f;-><init>(F)V

    .line 20
    .line 21
    .line 22
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    iput-object p1, p0, Leq0/c;->c:Ll2/j1;

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of v0, p1, Leq0/c;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Leq0/c;

    .line 10
    .line 11
    iget p0, p0, Leq0/c;->a:F

    .line 12
    .line 13
    iget p1, p1, Leq0/c;->a:F

    .line 14
    .line 15
    invoke-static {p0, p1}, Lt4/f;->a(FF)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    if-nez p0, :cond_2

    .line 20
    .line 21
    :goto_0
    const/4 p0, 0x0

    .line 22
    return p0

    .line 23
    :cond_2
    :goto_1
    const/4 p0, 0x1

    .line 24
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget p0, p0, Leq0/c;->a:F

    .line 2
    .line 3
    invoke-static {p0}, Ljava/lang/Float;->hashCode(F)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget p0, p0, Leq0/c;->a:F

    .line 2
    .line 3
    invoke-static {p0}, Lt4/f;->b(F)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "ToolbarState(initial="

    .line 8
    .line 9
    const-string v1, ")"

    .line 10
    .line 11
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method
