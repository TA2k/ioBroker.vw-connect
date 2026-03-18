.class public final Lk20/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lk20/m;


# direct methods
.method public synthetic constructor <init>(Lk20/m;I)V
    .locals 0

    .line 1
    iput p2, p0, Lk20/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lk20/j;->e:Lk20/m;

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
    iget p2, p0, Lk20/j;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/t;

    .line 7
    .line 8
    iget-object p0, p0, Lk20/j;->e:Lk20/m;

    .line 9
    .line 10
    iget-object p2, p0, Lk20/m;->p:Lug0/c;

    .line 11
    .line 12
    invoke-virtual {p2, p1}, Lug0/c;->a(Lne0/t;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    check-cast p1, Lk20/i;

    .line 20
    .line 21
    iget-boolean p1, p1, Lk20/i;->a:Z

    .line 22
    .line 23
    if-eqz p1, :cond_0

    .line 24
    .line 25
    iget-object p0, p0, Lk20/m;->j:Li20/f;

    .line 26
    .line 27
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    iget-object p0, p0, Lk20/m;->i:Ltr0/b;

    .line 32
    .line 33
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_0
    check-cast p1, Lzb0/a;

    .line 40
    .line 41
    iget-object p0, p0, Lk20/j;->e:Lk20/m;

    .line 42
    .line 43
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    check-cast p1, Lk20/i;

    .line 48
    .line 49
    const/4 p2, 0x2

    .line 50
    invoke-static {p1, p2}, Lk20/i;->a(Lk20/i;I)Lk20/i;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 55
    .line 56
    .line 57
    iget-object p0, p0, Lk20/m;->r:Lbd0/b;

    .line 58
    .line 59
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    return-object p0

    .line 65
    :pswitch_1
    check-cast p1, Lne0/t;

    .line 66
    .line 67
    iget-object p0, p0, Lk20/j;->e:Lk20/m;

    .line 68
    .line 69
    iget-object p1, p0, Lk20/m;->n:Lci0/e;

    .line 70
    .line 71
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    iget-object p1, p0, Lk20/m;->o:Lgb0/m;

    .line 75
    .line 76
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    iget-object p0, p0, Lk20/m;->j:Li20/f;

    .line 80
    .line 81
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    return-object p0

    .line 87
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
