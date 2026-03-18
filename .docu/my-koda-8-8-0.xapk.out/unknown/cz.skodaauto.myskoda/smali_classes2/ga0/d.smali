.class public final Lga0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lga0/o;


# direct methods
.method public synthetic constructor <init>(Lga0/o;I)V
    .locals 0

    .line 1
    iput p2, p0, Lga0/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lga0/d;->e:Lga0/o;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget p2, p0, Lga0/d;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Boolean;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 9
    .line 10
    .line 11
    move-result v9

    .line 12
    iget-object p0, p0, Lga0/d;->e:Lga0/o;

    .line 13
    .line 14
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    move-object v0, p1

    .line 19
    check-cast v0, Lga0/i;

    .line 20
    .line 21
    const/4 v8, 0x0

    .line 22
    const/16 v10, 0xff

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    const/4 v2, 0x0

    .line 26
    const/4 v3, 0x0

    .line 27
    const/4 v4, 0x0

    .line 28
    const/4 v5, 0x0

    .line 29
    const/4 v6, 0x0

    .line 30
    const/4 v7, 0x0

    .line 31
    invoke-static/range {v0 .. v10}, Lga0/i;->a(Lga0/i;Lql0/g;ZLlf0/i;Lga0/e;Ljava/util/List;ZZZZI)Lga0/i;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 36
    .line 37
    .line 38
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_0
    check-cast p1, Lss0/j0;

    .line 42
    .line 43
    new-instance p1, Lga0/i;

    .line 44
    .line 45
    const/4 p2, 0x0

    .line 46
    const/16 v0, 0x1ff

    .line 47
    .line 48
    invoke-direct {p1, p2, v0}, Lga0/i;-><init>(Ljava/util/List;I)V

    .line 49
    .line 50
    .line 51
    iget-object p0, p0, Lga0/d;->e:Lga0/o;

    .line 52
    .line 53
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 54
    .line 55
    .line 56
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    return-object p0

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
