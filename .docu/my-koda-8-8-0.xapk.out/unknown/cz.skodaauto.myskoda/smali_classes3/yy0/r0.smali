.class public final Lyy0/r0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lkotlin/jvm/internal/f0;


# direct methods
.method public synthetic constructor <init>(Lkotlin/jvm/internal/f0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lyy0/r0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lyy0/r0;->e:Lkotlin/jvm/internal/f0;

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
    .locals 0

    .line 1
    iget p2, p0, Lyy0/r0;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lyy0/r0;->e:Lkotlin/jvm/internal/f0;

    .line 7
    .line 8
    iput-object p1, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 9
    .line 10
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    return-object p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lyy0/r0;->e:Lkotlin/jvm/internal/f0;

    .line 14
    .line 15
    iput-object p1, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 16
    .line 17
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_1
    iget-object p2, p0, Lyy0/r0;->e:Lkotlin/jvm/internal/f0;

    .line 21
    .line 22
    iput-object p1, p2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 23
    .line 24
    new-instance p1, Lzy0/a;

    .line 25
    .line 26
    invoke-direct {p1, p0}, Lzy0/a;-><init>(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    throw p1

    .line 30
    :pswitch_2
    iget-object p2, p0, Lyy0/r0;->e:Lkotlin/jvm/internal/f0;

    .line 31
    .line 32
    iput-object p1, p2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 33
    .line 34
    new-instance p1, Lzy0/a;

    .line 35
    .line 36
    invoke-direct {p1, p0}, Lzy0/a;-><init>(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    throw p1

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
