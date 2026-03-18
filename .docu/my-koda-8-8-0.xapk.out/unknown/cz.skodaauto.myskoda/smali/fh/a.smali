.class public final synthetic Lfh/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ldi/a;


# direct methods
.method public synthetic constructor <init>(Ldi/a;I)V
    .locals 0

    .line 1
    iput p2, p0, Lfh/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lfh/a;->e:Ldi/a;

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
    .locals 8

    .line 1
    iget v0, p0, Lfh/a;->d:I

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
    move-object v2, p1

    .line 28
    check-cast v2, Ldh/u;

    .line 29
    .line 30
    new-instance p1, Lfh/g;

    .line 31
    .line 32
    new-instance v0, Ljd/b;

    .line 33
    .line 34
    const/4 v6, 0x0

    .line 35
    const/16 v7, 0xe

    .line 36
    .line 37
    const/4 v1, 0x2

    .line 38
    const-class v3, Ldh/u;

    .line 39
    .line 40
    const-string v4, "changeAuthMode"

    .line 41
    .line 42
    const-string v5, "changeAuthMode-gIAlu-s(Lcariad/charging/multicharge/kitten/wallboxes/models/ChangeAuthorizationModeRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 43
    .line 44
    invoke-direct/range {v0 .. v7}, Ljd/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 45
    .line 46
    .line 47
    iget-object p0, p0, Lfh/a;->e:Ldi/a;

    .line 48
    .line 49
    invoke-direct {p1, p0, v0}, Lfh/g;-><init>(Ldi/a;Lay0/n;)V

    .line 50
    .line 51
    .line 52
    return-object p1

    .line 53
    :pswitch_0
    const-string v0, "$this$sdkViewModel"

    .line 54
    .line 55
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    const-class v0, Ldh/u;

    .line 59
    .line 60
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 61
    .line 62
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    check-cast p1, Lii/a;

    .line 67
    .line 68
    invoke-virtual {p1, v0}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    move-object v2, p1

    .line 73
    check-cast v2, Ldh/u;

    .line 74
    .line 75
    new-instance p1, Lfh/g;

    .line 76
    .line 77
    new-instance v0, Lag/c;

    .line 78
    .line 79
    const/4 v6, 0x0

    .line 80
    const/16 v7, 0x10

    .line 81
    .line 82
    const/4 v1, 0x2

    .line 83
    const-class v3, Ldh/u;

    .line 84
    .line 85
    const-string v4, "changeAuthMode"

    .line 86
    .line 87
    const-string v5, "changeAuthMode-gIAlu-s(Lcariad/charging/multicharge/kitten/wallboxes/models/ChangeAuthorizationModeRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 88
    .line 89
    invoke-direct/range {v0 .. v7}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 90
    .line 91
    .line 92
    iget-object p0, p0, Lfh/a;->e:Ldi/a;

    .line 93
    .line 94
    invoke-direct {p1, p0, v0}, Lfh/g;-><init>(Ldi/a;Lay0/n;)V

    .line 95
    .line 96
    .line 97
    return-object p1

    .line 98
    nop

    .line 99
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
