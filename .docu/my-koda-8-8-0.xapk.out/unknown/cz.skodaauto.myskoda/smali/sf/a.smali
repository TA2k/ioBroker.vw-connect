.class public final synthetic Lsf/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Lyj/b;

.field public final synthetic h:Lxh/e;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Lyj/b;Lxh/e;I)V
    .locals 0

    .line 1
    iput p5, p0, Lsf/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lsf/a;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Lsf/a;->f:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p3, p0, Lsf/a;->g:Lyj/b;

    .line 8
    .line 9
    iput-object p4, p0, Lsf/a;->h:Lxh/e;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lsf/a;->d:I

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
    const-class v0, Lpf/f;

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
    move-object v1, p1

    .line 28
    check-cast v1, Lpf/f;

    .line 29
    .line 30
    new-instance p1, Lvf/c;

    .line 31
    .line 32
    new-instance v0, Lsf/c;

    .line 33
    .line 34
    const/4 v4, 0x0

    .line 35
    const/4 v5, 0x1

    .line 36
    iget-object v2, p0, Lsf/a;->e:Ljava/lang/String;

    .line 37
    .line 38
    iget-object v3, p0, Lsf/a;->f:Ljava/lang/String;

    .line 39
    .line 40
    invoke-direct/range {v0 .. v5}, Lsf/c;-><init>(Lpf/f;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 41
    .line 42
    .line 43
    iget-object v1, p0, Lsf/a;->g:Lyj/b;

    .line 44
    .line 45
    iget-object p0, p0, Lsf/a;->h:Lxh/e;

    .line 46
    .line 47
    invoke-direct {p1, v0, v1, p0}, Lvf/c;-><init>(Lsf/c;Lyj/b;Lxh/e;)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_0
    const-string v0, "$this$sdkViewModel"

    .line 52
    .line 53
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    const-class v0, Lpf/f;

    .line 57
    .line 58
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 59
    .line 60
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    check-cast p1, Lii/a;

    .line 65
    .line 66
    invoke-virtual {p1, v0}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    move-object v1, p1

    .line 71
    check-cast v1, Lpf/f;

    .line 72
    .line 73
    new-instance p1, Lsf/f;

    .line 74
    .line 75
    new-instance v0, Lsf/c;

    .line 76
    .line 77
    const/4 v4, 0x0

    .line 78
    const/4 v5, 0x0

    .line 79
    iget-object v2, p0, Lsf/a;->e:Ljava/lang/String;

    .line 80
    .line 81
    iget-object v3, p0, Lsf/a;->f:Ljava/lang/String;

    .line 82
    .line 83
    invoke-direct/range {v0 .. v5}, Lsf/c;-><init>(Lpf/f;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 84
    .line 85
    .line 86
    iget-object v1, p0, Lsf/a;->g:Lyj/b;

    .line 87
    .line 88
    iget-object p0, p0, Lsf/a;->h:Lxh/e;

    .line 89
    .line 90
    invoke-direct {p1, v0, v1, p0}, Lsf/f;-><init>(Lsf/c;Lyj/b;Lxh/e;)V

    .line 91
    .line 92
    .line 93
    return-object p1

    .line 94
    nop

    .line 95
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
