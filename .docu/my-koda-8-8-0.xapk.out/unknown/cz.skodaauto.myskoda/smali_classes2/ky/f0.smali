.class public final Lky/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lf40/h3;

.field public final b:Lf40/f3;

.field public final c:Lf40/i3;

.field public final d:Lf40/g3;

.field public final e:Lb00/m;

.field public final f:Le60/n;

.field public final g:Lt00/h;

.field public final h:Lk90/p;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lb00/m;->e:Lyy0/m;

    .line 2
    .line 3
    return-void
.end method

.method public constructor <init>(Lf40/h3;Lf40/f3;Lf40/i3;Lf40/g3;Lb00/m;Le60/n;Lt00/h;Lk90/p;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lky/f0;->a:Lf40/h3;

    .line 5
    .line 6
    iput-object p2, p0, Lky/f0;->b:Lf40/f3;

    .line 7
    .line 8
    iput-object p3, p0, Lky/f0;->c:Lf40/i3;

    .line 9
    .line 10
    iput-object p4, p0, Lky/f0;->d:Lf40/g3;

    .line 11
    .line 12
    iput-object p5, p0, Lky/f0;->e:Lb00/m;

    .line 13
    .line 14
    iput-object p6, p0, Lky/f0;->f:Le60/n;

    .line 15
    .line 16
    iput-object p7, p0, Lky/f0;->g:Lt00/h;

    .line 17
    .line 18
    iput-object p8, p0, Lky/f0;->h:Lk90/p;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lky/c0;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lky/f0;->b(Lky/c0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lky/c0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lky/e0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lky/e0;

    .line 7
    .line 8
    iget v1, v0, Lky/e0;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lky/e0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lky/e0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lky/e0;-><init>(Lky/f0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lky/e0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lky/e0;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_3

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iget-object p2, p1, Lky/c0;->a:Lly/b;

    .line 52
    .line 53
    if-nez p2, :cond_3

    .line 54
    .line 55
    const/4 p2, -0x1

    .line 56
    goto :goto_1

    .line 57
    :cond_3
    sget-object v2, Lky/d0;->a:[I

    .line 58
    .line 59
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 60
    .line 61
    .line 62
    move-result p2

    .line 63
    aget p2, v2, p2

    .line 64
    .line 65
    :goto_1
    packed-switch p2, :pswitch_data_0

    .line 66
    .line 67
    .line 68
    const/4 p0, 0x0

    .line 69
    goto :goto_2

    .line 70
    :pswitch_0
    iget-object p0, p0, Lky/f0;->h:Lk90/p;

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :pswitch_1
    iget-object p0, p0, Lky/f0;->f:Le60/n;

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :pswitch_2
    iget-object p0, p0, Lky/f0;->e:Lb00/m;

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :pswitch_3
    iget-object p0, p0, Lky/f0;->c:Lf40/i3;

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :pswitch_4
    iget-object p0, p0, Lky/f0;->d:Lf40/g3;

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :pswitch_5
    iget-object p0, p0, Lky/f0;->a:Lf40/h3;

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :pswitch_6
    iget-object p0, p0, Lky/f0;->b:Lf40/f3;

    .line 89
    .line 90
    goto :goto_2

    .line 91
    :pswitch_7
    iget-object p0, p0, Lky/f0;->g:Lt00/h;

    .line 92
    .line 93
    :goto_2
    if-eqz p0, :cond_5

    .line 94
    .line 95
    iget-object p1, p1, Lky/c0;->b:Ljava/util/Map;

    .line 96
    .line 97
    iput v3, v0, Lky/e0;->f:I

    .line 98
    .line 99
    invoke-interface {p0, p1, v0}, Ltr0/c;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p2

    .line 103
    if-ne p2, v1, :cond_4

    .line 104
    .line 105
    return-object v1

    .line 106
    :cond_4
    :goto_3
    check-cast p2, Lne0/t;

    .line 107
    .line 108
    if-eqz p2, :cond_5

    .line 109
    .line 110
    return-object p2

    .line 111
    :cond_5
    new-instance p0, Lne0/e;

    .line 112
    .line 113
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 114
    .line 115
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    return-object p0

    .line 119
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
