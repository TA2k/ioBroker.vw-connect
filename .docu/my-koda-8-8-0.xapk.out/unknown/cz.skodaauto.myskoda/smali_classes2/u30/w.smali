.class public final Lu30/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lu30/j;

.field public final b:Lu30/k;


# direct methods
.method public constructor <init>(Lu30/j;Lu30/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu30/w;->a:Lu30/j;

    .line 5
    .line 6
    iput-object p2, p0, Lu30/w;->b:Lu30/k;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Ljava/lang/String;

    .line 5
    .line 6
    iget-object v2, p0, Lu30/w;->b:Lu30/k;

    .line 7
    .line 8
    check-cast v2, Ls30/a;

    .line 9
    .line 10
    iget-object v3, v2, Ls30/a;->b:Lyy0/c2;

    .line 11
    .line 12
    invoke-virtual {v2}, Ls30/a;->a()Ljava/util/ArrayList;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    :cond_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-eqz v4, :cond_1

    .line 25
    .line 26
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    move-object v5, v4

    .line 31
    check-cast v5, Lv30/f;

    .line 32
    .line 33
    iget-object v5, v5, Lv30/f;->a:Ljava/lang/String;

    .line 34
    .line 35
    invoke-static {v5, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v5

    .line 39
    if-eqz v5, :cond_0

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    const/4 v4, 0x0

    .line 43
    :goto_0
    invoke-virtual {v3, v4}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    iget-object p0, p0, Lu30/w;->a:Lu30/j;

    .line 47
    .line 48
    check-cast p0, Liy/b;

    .line 49
    .line 50
    sget-object v1, Lly/b;->D1:Lly/b;

    .line 51
    .line 52
    invoke-interface {p0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 53
    .line 54
    .line 55
    return-object v0
.end method
