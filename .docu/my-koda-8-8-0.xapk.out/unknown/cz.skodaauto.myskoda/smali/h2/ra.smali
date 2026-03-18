.class public final Lh2/ra;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lg1/q;

.field public final b:Lay0/k;


# direct methods
.method public constructor <init>(Lh2/sa;Lay0/k;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lg1/q;

    .line 5
    .line 6
    invoke-direct {v0, p1}, Lg1/q;-><init>(Lh2/sa;)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lh2/ra;->a:Lg1/q;

    .line 10
    .line 11
    iput-object p2, p0, Lh2/ra;->b:Lay0/k;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a()Lh2/sa;
    .locals 2

    .line 1
    iget-object p0, p0, Lh2/ra;->a:Lg1/q;

    .line 2
    .line 3
    iget-object v0, p0, Lg1/q;->i:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Ll2/f1;

    .line 6
    .line 7
    iget-object p0, p0, Lg1/q;->i:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Ll2/f1;

    .line 10
    .line 11
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/4 v1, 0x0

    .line 16
    cmpg-float v0, v0, v1

    .line 17
    .line 18
    if-nez v0, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    :goto_0
    sget-object p0, Lh2/sa;->f:Lh2/sa;

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_1
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    cmpl-float p0, p0, v1

    .line 39
    .line 40
    if-lez p0, :cond_2

    .line 41
    .line 42
    sget-object p0, Lh2/sa;->d:Lh2/sa;

    .line 43
    .line 44
    return-object p0

    .line 45
    :cond_2
    sget-object p0, Lh2/sa;->e:Lh2/sa;

    .line 46
    .line 47
    return-object p0
.end method
