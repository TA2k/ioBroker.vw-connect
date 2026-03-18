.class public final Lh40/x2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/z2;


# direct methods
.method public synthetic constructor <init>(Lh40/z2;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh40/x2;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/x2;->e:Lh40/z2;

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
    .locals 6

    .line 1
    iget p2, p0, Lh40/x2;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/c;

    .line 7
    .line 8
    iget-object p0, p0, Lh40/x2;->e:Lh40/z2;

    .line 9
    .line 10
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    move-object v0, p2

    .line 15
    check-cast v0, Lh40/y2;

    .line 16
    .line 17
    iget-object p2, p0, Lh40/z2;->i:Lij0/a;

    .line 18
    .line 19
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    const/4 v4, 0x0

    .line 24
    const/16 v5, 0xd

    .line 25
    .line 26
    const/4 v1, 0x0

    .line 27
    const/4 v3, 0x0

    .line 28
    invoke-static/range {v0 .. v5}, Lh40/y2;->a(Lh40/y2;ZLql0/g;Lg40/u0;Lg40/i0;I)Lh40/y2;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 33
    .line 34
    .line 35
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_0
    move-object v3, p1

    .line 39
    check-cast v3, Lg40/u0;

    .line 40
    .line 41
    iget-object p0, p0, Lh40/x2;->e:Lh40/z2;

    .line 42
    .line 43
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    move-object v0, p1

    .line 48
    check-cast v0, Lh40/y2;

    .line 49
    .line 50
    const/4 v4, 0x0

    .line 51
    const/16 v5, 0xb

    .line 52
    .line 53
    const/4 v1, 0x0

    .line 54
    const/4 v2, 0x0

    .line 55
    invoke-static/range {v0 .. v5}, Lh40/y2;->a(Lh40/y2;ZLql0/g;Lg40/u0;Lg40/i0;I)Lh40/y2;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 60
    .line 61
    .line 62
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    return-object p0

    .line 65
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
