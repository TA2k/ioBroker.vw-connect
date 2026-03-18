.class public final Ls10/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ls10/d0;


# direct methods
.method public synthetic constructor <init>(Ls10/d0;I)V
    .locals 0

    .line 1
    iput p2, p0, Ls10/b0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ls10/b0;->e:Ls10/d0;

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
    .locals 10

    .line 1
    iget p2, p0, Ls10/b0;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lss0/j0;

    .line 7
    .line 8
    new-instance p1, Ls10/c0;

    .line 9
    .line 10
    const/4 p2, 0x0

    .line 11
    const/16 v0, 0xff

    .line 12
    .line 13
    invoke-direct {p1, p2, v0}, Ls10/c0;-><init>(Llf0/i;I)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Ls10/b0;->e:Ls10/d0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 19
    .line 20
    .line 21
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_0
    check-cast p1, Ljava/lang/Boolean;

    .line 25
    .line 26
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 27
    .line 28
    .line 29
    move-result v8

    .line 30
    iget-object p0, p0, Ls10/b0;->e:Ls10/d0;

    .line 31
    .line 32
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    move-object v0, p1

    .line 37
    check-cast v0, Ls10/c0;

    .line 38
    .line 39
    const/4 v7, 0x0

    .line 40
    const/16 v9, 0x7f

    .line 41
    .line 42
    const/4 v1, 0x0

    .line 43
    const/4 v2, 0x0

    .line 44
    const/4 v3, 0x0

    .line 45
    const/4 v4, 0x0

    .line 46
    const/4 v5, 0x0

    .line 47
    const/4 v6, 0x0

    .line 48
    invoke-static/range {v0 .. v9}, Ls10/c0;->a(Ls10/c0;Llf0/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZI)Ls10/c0;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 53
    .line 54
    .line 55
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    return-object p0

    .line 58
    nop

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
