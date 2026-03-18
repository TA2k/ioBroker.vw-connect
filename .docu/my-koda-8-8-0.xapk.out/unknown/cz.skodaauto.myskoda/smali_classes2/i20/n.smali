.class public final Li20/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Li20/h;

.field public final b:Lg20/a;


# direct methods
.method public constructor <init>(Li20/h;Lg20/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li20/n;->a:Li20/h;

    .line 5
    .line 6
    iput-object p2, p0, Li20/n;->b:Lg20/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 8

    .line 1
    iget-object v0, p0, Li20/n;->b:Lg20/a;

    .line 2
    .line 3
    iget-object v0, v0, Lg20/a;->a:Lj20/c;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_1

    .line 7
    .line 8
    iget-object v2, v0, Lj20/c;->a:Lss0/n;

    .line 9
    .line 10
    iget-object v0, v0, Lj20/c;->b:Ljava/lang/String;

    .line 11
    .line 12
    const-string v3, "enrollmentVin"

    .line 13
    .line 14
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Li20/n;->a:Li20/h;

    .line 18
    .line 19
    iget-object v3, p0, Li20/h;->b:Lsg0/a;

    .line 20
    .line 21
    iput-object v2, v3, Lsg0/a;->b:Lss0/n;

    .line 22
    .line 23
    iput-object v0, v3, Lsg0/a;->a:Ljava/lang/String;

    .line 24
    .line 25
    iget-object v0, v3, Lsg0/a;->d:Lvg0/c;

    .line 26
    .line 27
    iget-object p0, p0, Li20/h;->a:Li20/c;

    .line 28
    .line 29
    check-cast p0, Liy/b;

    .line 30
    .line 31
    new-instance v2, Lul0/c;

    .line 32
    .line 33
    sget-object v3, Lly/b;->Z:Lly/b;

    .line 34
    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    invoke-static {v0}, Lrp/d;->c(Lvg0/c;)Lly/b;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    :cond_0
    move-object v5, v1

    .line 42
    const/4 v6, 0x0

    .line 43
    const/16 v7, 0x38

    .line 44
    .line 45
    const/4 v4, 0x1

    .line 46
    invoke-direct/range {v2 .. v7}, Lul0/c;-><init>(Lul0/f;ZLul0/f;Ljava/util/List;I)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p0, v2}, Liy/b;->b(Lul0/e;)V

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_1
    new-instance v0, Lhz/a;

    .line 54
    .line 55
    const/16 v2, 0xc

    .line 56
    .line 57
    invoke-direct {v0, v2}, Lhz/a;-><init>(I)V

    .line 58
    .line 59
    .line 60
    invoke-static {v1, p0, v0}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 61
    .line 62
    .line 63
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 64
    .line 65
    return-object p0
.end method
