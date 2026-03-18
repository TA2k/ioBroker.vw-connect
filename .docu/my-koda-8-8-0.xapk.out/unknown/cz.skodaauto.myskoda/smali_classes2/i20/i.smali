.class public final Li20/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Li20/c;

.field public final b:Lsg0/a;

.field public final c:Lg20/a;


# direct methods
.method public constructor <init>(Li20/c;Lsg0/a;Lg20/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li20/i;->a:Li20/c;

    .line 5
    .line 6
    iput-object p2, p0, Li20/i;->b:Lsg0/a;

    .line 7
    .line 8
    iput-object p3, p0, Li20/i;->c:Lg20/a;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lj20/c;)V
    .locals 6

    .line 1
    iget-object v0, p0, Li20/i;->c:Lg20/a;

    .line 2
    .line 3
    iput-object p1, v0, Lg20/a;->a:Lj20/c;

    .line 4
    .line 5
    iget-object p1, p0, Li20/i;->b:Lsg0/a;

    .line 6
    .line 7
    iget-object p1, p1, Lsg0/a;->d:Lvg0/c;

    .line 8
    .line 9
    iget-object p0, p0, Li20/i;->a:Li20/c;

    .line 10
    .line 11
    check-cast p0, Liy/b;

    .line 12
    .line 13
    new-instance v0, Lul0/c;

    .line 14
    .line 15
    sget-object v1, Lly/b;->Y:Lly/b;

    .line 16
    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    invoke-static {p1}, Lrp/d;->c(Lvg0/c;)Lly/b;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    :goto_0
    move-object v3, p1

    .line 24
    goto :goto_1

    .line 25
    :cond_0
    const/4 p1, 0x0

    .line 26
    goto :goto_0

    .line 27
    :goto_1
    const/4 v4, 0x0

    .line 28
    const/16 v5, 0x38

    .line 29
    .line 30
    const/4 v2, 0x1

    .line 31
    invoke-direct/range {v0 .. v5}, Lul0/c;-><init>(Lul0/f;ZLul0/f;Ljava/util/List;I)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, v0}, Liy/b;->b(Lul0/e;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lj20/c;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Li20/i;->a(Lj20/c;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
