.class public final Lvu/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lqu/c;


# direct methods
.method public synthetic constructor <init>(Lqu/c;I)V
    .locals 0

    .line 1
    iput p2, p0, Lvu/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lvu/b;->e:Lqu/c;

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
    iget p2, p0, Lvu/b;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/util/List;

    .line 7
    .line 8
    iget-object p0, p0, Lvu/b;->e:Lqu/c;

    .line 9
    .line 10
    iget-object p2, p0, Lqu/c;->g:Lap0/o;

    .line 11
    .line 12
    invoke-virtual {p2}, Lap0/o;->M()V

    .line 13
    .line 14
    .line 15
    :try_start_0
    invoke-interface {p2}, Lru/a;->g()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 16
    .line 17
    .line 18
    invoke-virtual {p2}, Lap0/o;->X()V

    .line 19
    .line 20
    .line 21
    check-cast p1, Ljava/util/Collection;

    .line 22
    .line 23
    iget-object p2, p0, Lqu/c;->g:Lap0/o;

    .line 24
    .line 25
    invoke-virtual {p2}, Lap0/o;->M()V

    .line 26
    .line 27
    .line 28
    :try_start_1
    invoke-interface {p2, p1}, Lru/a;->e(Ljava/util/Collection;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 29
    .line 30
    .line 31
    invoke-virtual {p2}, Lap0/o;->X()V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Lqu/c;->c()V

    .line 35
    .line 36
    .line 37
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0

    .line 40
    :catchall_0
    move-exception p0

    .line 41
    invoke-virtual {p2}, Lap0/o;->X()V

    .line 42
    .line 43
    .line 44
    throw p0

    .line 45
    :catchall_1
    move-exception p0

    .line 46
    invoke-virtual {p2}, Lap0/o;->X()V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :pswitch_0
    check-cast p1, Ljava/lang/Boolean;

    .line 51
    .line 52
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 53
    .line 54
    .line 55
    move-result p1

    .line 56
    if-nez p1, :cond_0

    .line 57
    .line 58
    iget-object p0, p0, Lvu/b;->e:Lqu/c;

    .line 59
    .line 60
    invoke-virtual {p0}, Lqu/c;->a()V

    .line 61
    .line 62
    .line 63
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 64
    .line 65
    return-object p0

    .line 66
    nop

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
