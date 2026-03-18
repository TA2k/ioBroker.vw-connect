.class public final Li20/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Li20/c;

.field public final b:Lsg0/a;


# direct methods
.method public constructor <init>(Li20/c;Lsg0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li20/h;->a:Li20/c;

    .line 5
    .line 6
    iput-object p2, p0, Li20/h;->b:Lsg0/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 8

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lvg0/b;

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget-object v1, p0, Li20/h;->b:Lsg0/a;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    iput-object v2, v1, Lsg0/a;->b:Lss0/n;

    .line 13
    .line 14
    iput-object v2, v1, Lsg0/a;->a:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v1, v1, Lsg0/a;->d:Lvg0/c;

    .line 17
    .line 18
    iget-object p0, p0, Li20/h;->a:Li20/c;

    .line 19
    .line 20
    check-cast p0, Liy/b;

    .line 21
    .line 22
    new-instance v2, Lul0/c;

    .line 23
    .line 24
    sget-object v3, Lly/b;->Z:Lly/b;

    .line 25
    .line 26
    if-eqz v1, :cond_0

    .line 27
    .line 28
    invoke-static {v1}, Lrp/d;->c(Lvg0/c;)Lly/b;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    :goto_0
    move-object v5, v1

    .line 33
    goto :goto_1

    .line 34
    :cond_0
    const/4 v1, 0x0

    .line 35
    goto :goto_0

    .line 36
    :goto_1
    const/4 v6, 0x0

    .line 37
    const/16 v7, 0x38

    .line 38
    .line 39
    const/4 v4, 0x1

    .line 40
    invoke-direct/range {v2 .. v7}, Lul0/c;-><init>(Lul0/f;ZLul0/f;Ljava/util/List;I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0, v2}, Liy/b;->b(Lul0/e;)V

    .line 44
    .line 45
    .line 46
    return-object v0
.end method
