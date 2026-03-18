.class public final synthetic Llh/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ldi/b;


# direct methods
.method public synthetic constructor <init>(Ldi/b;I)V
    .locals 0

    .line 1
    iput p2, p0, Llh/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Llh/a;->e:Ldi/b;

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
    .locals 4

    .line 1
    iget v0, p0, Llh/a;->d:I

    .line 2
    .line 3
    check-cast p1, Lhi/a;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "$this$sdkViewModel"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-class v0, Ldh/u;

    .line 14
    .line 15
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast p1, Lii/a;

    .line 22
    .line 23
    invoke-virtual {p1, v0}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    check-cast p1, Ldh/u;

    .line 28
    .line 29
    new-instance v0, Llh/h;

    .line 30
    .line 31
    new-instance v1, Llh/b;

    .line 32
    .line 33
    const/4 v2, 0x0

    .line 34
    const/4 v3, 0x1

    .line 35
    iget-object p0, p0, Llh/a;->e:Ldi/b;

    .line 36
    .line 37
    invoke-direct {v1, p1, p0, v2, v3}, Llh/b;-><init>(Ldh/u;Ldi/b;Lkotlin/coroutines/Continuation;I)V

    .line 38
    .line 39
    .line 40
    invoke-direct {v0, p0, v1}, Llh/h;-><init>(Ldi/b;Lay0/n;)V

    .line 41
    .line 42
    .line 43
    return-object v0

    .line 44
    :pswitch_0
    const-string v0, "$this$sdkViewModel"

    .line 45
    .line 46
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    const-class v0, Ldh/u;

    .line 50
    .line 51
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 52
    .line 53
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    check-cast p1, Lii/a;

    .line 58
    .line 59
    invoke-virtual {p1, v0}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    check-cast p1, Ldh/u;

    .line 64
    .line 65
    new-instance v0, Llh/h;

    .line 66
    .line 67
    new-instance v1, Llh/b;

    .line 68
    .line 69
    const/4 v2, 0x0

    .line 70
    const/4 v3, 0x0

    .line 71
    iget-object p0, p0, Llh/a;->e:Ldi/b;

    .line 72
    .line 73
    invoke-direct {v1, p1, p0, v2, v3}, Llh/b;-><init>(Ldh/u;Ldi/b;Lkotlin/coroutines/Continuation;I)V

    .line 74
    .line 75
    .line 76
    invoke-direct {v0, p0, v1}, Llh/h;-><init>(Ldi/b;Lay0/n;)V

    .line 77
    .line 78
    .line 79
    return-object v0

    .line 80
    nop

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
