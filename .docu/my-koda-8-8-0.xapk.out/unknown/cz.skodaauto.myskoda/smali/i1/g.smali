.class public final Li1/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/ArrayList;

.field public final synthetic f:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;Ll2/b1;I)V
    .locals 0

    .line 1
    iput p3, p0, Li1/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li1/g;->e:Ljava/util/ArrayList;

    .line 4
    .line 5
    iput-object p2, p0, Li1/g;->f:Ll2/b1;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget p2, p0, Li1/g;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Li1/k;

    .line 7
    .line 8
    instance-of p2, p1, Li1/n;

    .line 9
    .line 10
    iget-object v0, p0, Li1/g;->e:Ljava/util/ArrayList;

    .line 11
    .line 12
    if-eqz p2, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    instance-of p2, p1, Li1/o;

    .line 19
    .line 20
    if-eqz p2, :cond_1

    .line 21
    .line 22
    check-cast p1, Li1/o;

    .line 23
    .line 24
    iget-object p1, p1, Li1/o;->a:Li1/n;

    .line 25
    .line 26
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    instance-of p2, p1, Li1/m;

    .line 31
    .line 32
    if-eqz p2, :cond_2

    .line 33
    .line 34
    check-cast p1, Li1/m;

    .line 35
    .line 36
    iget-object p1, p1, Li1/m;->a:Li1/n;

    .line 37
    .line 38
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    :cond_2
    :goto_0
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    xor-int/lit8 p1, p1, 0x1

    .line 46
    .line 47
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    iget-object p0, p0, Li1/g;->f:Ll2/b1;

    .line 52
    .line 53
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 57
    .line 58
    return-object p0

    .line 59
    :pswitch_0
    check-cast p1, Li1/k;

    .line 60
    .line 61
    instance-of p2, p1, Li1/e;

    .line 62
    .line 63
    iget-object v0, p0, Li1/g;->e:Ljava/util/ArrayList;

    .line 64
    .line 65
    if-eqz p2, :cond_3

    .line 66
    .line 67
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_3
    instance-of p2, p1, Li1/f;

    .line 72
    .line 73
    if-eqz p2, :cond_4

    .line 74
    .line 75
    check-cast p1, Li1/f;

    .line 76
    .line 77
    iget-object p1, p1, Li1/f;->a:Li1/e;

    .line 78
    .line 79
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    :cond_4
    :goto_1
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 83
    .line 84
    .line 85
    move-result p1

    .line 86
    xor-int/lit8 p1, p1, 0x1

    .line 87
    .line 88
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    iget-object p0, p0, Li1/g;->f:Ll2/b1;

    .line 93
    .line 94
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 98
    .line 99
    return-object p0

    .line 100
    nop

    .line 101
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
