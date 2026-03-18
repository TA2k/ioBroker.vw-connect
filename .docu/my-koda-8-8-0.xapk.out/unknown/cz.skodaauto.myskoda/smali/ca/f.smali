.class public final synthetic Lca/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lca/g;


# direct methods
.method public synthetic constructor <init>(Lca/g;I)V
    .locals 0

    .line 1
    iput p2, p0, Lca/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lca/f;->e:Lca/g;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lca/f;->d:I

    .line 2
    .line 3
    check-cast p1, Lz9/u;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "destination"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lca/f;->e:Lca/g;

    .line 14
    .line 15
    iget-object p0, p0, Lca/g;->l:Ljava/util/LinkedHashMap;

    .line 16
    .line 17
    iget-object p1, p1, Lz9/u;->e:Lca/j;

    .line 18
    .line 19
    iget p1, p1, Lca/j;->a:I

    .line 20
    .line 21
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-interface {p0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    :goto_0
    xor-int/lit8 p0, p0, 0x1

    .line 30
    .line 31
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_0
    const-string v0, "destination"

    .line 37
    .line 38
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Lca/f;->e:Lca/g;

    .line 42
    .line 43
    iget-object p0, p0, Lca/g;->l:Ljava/util/LinkedHashMap;

    .line 44
    .line 45
    iget-object p1, p1, Lz9/u;->e:Lca/j;

    .line 46
    .line 47
    iget p1, p1, Lca/j;->a:I

    .line 48
    .line 49
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    invoke-interface {p0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    goto :goto_0

    .line 58
    nop

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
