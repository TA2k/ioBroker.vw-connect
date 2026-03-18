.class public final Lew/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lkw/p;

.field public final b:Lkw/p;

.field public final c:Lkw/p;

.field public d:Z

.field public final e:Ll2/f1;

.field public final f:Ll2/j1;

.field public final g:Z


# direct methods
.method public constructor <init>(Lkw/p;Lkw/p;Lkw/p;FZ)V
    .locals 2

    .line 1
    const-string v0, "initialZoom"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "minZoom"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "maxZoom"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    new-instance v0, Lgy0/e;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, v1, v1}, Lgy0/e;-><init>(FF)V

    .line 23
    .line 24
    .line 25
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    iput-object v0, p0, Lew/j;->f:Ll2/j1;

    .line 30
    .line 31
    const/4 v0, 0x1

    .line 32
    iput-boolean v0, p0, Lew/j;->g:Z

    .line 33
    .line 34
    iput-object p1, p0, Lew/j;->a:Lkw/p;

    .line 35
    .line 36
    iput-object p2, p0, Lew/j;->b:Lkw/p;

    .line 37
    .line 38
    iput-object p3, p0, Lew/j;->c:Lkw/p;

    .line 39
    .line 40
    new-instance p1, Ll2/f1;

    .line 41
    .line 42
    invoke-direct {p1, p4}, Ll2/f1;-><init>(F)V

    .line 43
    .line 44
    .line 45
    iput-object p1, p0, Lew/j;->e:Ll2/f1;

    .line 46
    .line 47
    iput-boolean p5, p0, Lew/j;->d:Z

    .line 48
    .line 49
    return-void
.end method


# virtual methods
.method public final a(F)V
    .locals 1

    .line 1
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iget-object v0, p0, Lew/j;->f:Ll2/j1;

    .line 6
    .line 7
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Lgy0/f;

    .line 12
    .line 13
    invoke-static {p1, v0}, Lkp/r9;->i(Ljava/lang/Comparable;Lgy0/f;)Ljava/lang/Comparable;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    check-cast p1, Ljava/lang/Number;

    .line 18
    .line 19
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    iget-object p0, p0, Lew/j;->e:Ll2/f1;

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Ll2/f1;->p(F)V

    .line 26
    .line 27
    .line 28
    return-void
.end method
