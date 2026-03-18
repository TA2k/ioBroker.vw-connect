.class public final Lew/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Lkw/d;

.field public final synthetic e:Lmw/a;

.field public final synthetic f:Lew/i;

.field public final synthetic g:Lew/j;

.field public final synthetic h:Lmw/l;


# direct methods
.method public constructor <init>(Lkw/d;Lmw/a;Lew/i;Lew/j;Lmw/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lew/d;->d:Lkw/d;

    .line 5
    .line 6
    iput-object p2, p0, Lew/d;->e:Lmw/a;

    .line 7
    .line 8
    iput-object p3, p0, Lew/d;->f:Lew/i;

    .line 9
    .line 10
    iput-object p4, p0, Lew/d;->g:Lew/j;

    .line 11
    .line 12
    iput-object p5, p0, Lew/d;->h:Lmw/l;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    check-cast p1, Lk1/q;

    .line 2
    .line 3
    move-object v5, p2

    .line 4
    check-cast v5, Ll2/o;

    .line 5
    .line 6
    check-cast p3, Ljava/lang/Number;

    .line 7
    .line 8
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 9
    .line 10
    .line 11
    move-result p2

    .line 12
    const-string p3, "$this$CartesianChartHostBox"

    .line 13
    .line 14
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    and-int/lit8 p1, p2, 0x11

    .line 18
    .line 19
    const/16 p2, 0x10

    .line 20
    .line 21
    if-ne p1, p2, :cond_1

    .line 22
    .line 23
    move-object p1, v5

    .line 24
    check-cast p1, Ll2/t;

    .line 25
    .line 26
    invoke-virtual {p1}, Ll2/t;->A()Z

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    if-nez p2, :cond_0

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 34
    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    :goto_0
    const-string p1, "<this>"

    .line 38
    .line 39
    iget-object p2, p0, Lew/d;->h:Lmw/l;

    .line 40
    .line 41
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    new-instance v4, Lmw/m;

    .line 45
    .line 46
    invoke-direct {v4, p2}, Lmw/m;-><init>(Lmw/l;)V

    .line 47
    .line 48
    .line 49
    const/4 v6, 0x0

    .line 50
    iget-object v0, p0, Lew/d;->d:Lkw/d;

    .line 51
    .line 52
    iget-object v1, p0, Lew/d;->e:Lmw/a;

    .line 53
    .line 54
    iget-object v2, p0, Lew/d;->f:Lew/i;

    .line 55
    .line 56
    iget-object v3, p0, Lew/d;->g:Lew/j;

    .line 57
    .line 58
    invoke-static/range {v0 .. v6}, Lew/e;->c(Lkw/d;Lmw/a;Lew/i;Lew/j;Lmw/m;Ll2/o;I)V

    .line 59
    .line 60
    .line 61
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 62
    .line 63
    return-object p0
.end method
