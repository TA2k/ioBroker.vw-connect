.class public final La3/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnDragListener;
.implements La3/c;


# instance fields
.field public final a:La3/h;

.field public final b:Landroidx/collection/g;

.field public final c:Landroidx/compose/ui/draganddrop/AndroidDragAndDropManager$modifier$1;


# direct methods
.method public constructor <init>(Laj/a;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance p1, La3/h;

    .line 5
    .line 6
    invoke-direct {p1}, Lx2/r;-><init>()V

    .line 7
    .line 8
    .line 9
    const-wide/16 v0, 0x0

    .line 10
    .line 11
    iput-wide v0, p1, La3/h;->t:J

    .line 12
    .line 13
    iput-object p1, p0, La3/a;->a:La3/h;

    .line 14
    .line 15
    new-instance p1, Landroidx/collection/g;

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    invoke-direct {p1, v0}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, La3/a;->b:Landroidx/collection/g;

    .line 22
    .line 23
    new-instance p1, Landroidx/compose/ui/draganddrop/AndroidDragAndDropManager$modifier$1;

    .line 24
    .line 25
    invoke-direct {p1, p0}, Landroidx/compose/ui/draganddrop/AndroidDragAndDropManager$modifier$1;-><init>(La3/a;)V

    .line 26
    .line 27
    .line 28
    iput-object p1, p0, La3/a;->c:Landroidx/compose/ui/draganddrop/AndroidDragAndDropManager$modifier$1;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final onDrag(Landroid/view/View;Landroid/view/DragEvent;)Z
    .locals 4

    .line 1
    new-instance p1, Lbu/c;

    .line 2
    .line 3
    const/4 v0, 0x2

    .line 4
    invoke-direct {p1, p2, v0}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p2}, Landroid/view/DragEvent;->getAction()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    iget-object v0, p0, La3/a;->b:Landroidx/collection/g;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    iget-object p0, p0, La3/a;->a:La3/h;

    .line 15
    .line 16
    packed-switch p2, :pswitch_data_0

    .line 17
    .line 18
    .line 19
    return v1

    .line 20
    :pswitch_0
    invoke-virtual {p0, p1}, La3/h;->Z0(Lbu/c;)V

    .line 21
    .line 22
    .line 23
    return v1

    .line 24
    :pswitch_1
    invoke-virtual {p0, p1}, La3/h;->Y0(Lbu/c;)V

    .line 25
    .line 26
    .line 27
    return v1

    .line 28
    :pswitch_2
    new-instance p2, La3/f;

    .line 29
    .line 30
    const/4 v2, 0x0

    .line 31
    invoke-direct {p2, p1, v2}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p2, p0}, La3/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    sget-object v2, Lv3/b2;->d:Lv3/b2;

    .line 39
    .line 40
    if-eq p1, v2, :cond_0

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    invoke-static {p0, p2}, Lv3/f;->C(Lv3/c2;Lay0/k;)V

    .line 44
    .line 45
    .line 46
    :goto_0
    invoke-virtual {v0}, Landroidx/collection/g;->clear()V

    .line 47
    .line 48
    .line 49
    return v1

    .line 50
    :pswitch_3
    invoke-virtual {p0, p1}, La3/h;->X0(Lbu/c;)Z

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    return p0

    .line 55
    :pswitch_4
    invoke-virtual {p0, p1}, La3/h;->a1(Lbu/c;)V

    .line 56
    .line 57
    .line 58
    return v1

    .line 59
    :pswitch_5
    new-instance p2, Lkotlin/jvm/internal/b0;

    .line 60
    .line 61
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 62
    .line 63
    .line 64
    new-instance v1, La3/e;

    .line 65
    .line 66
    invoke-direct {v1, p1, p0, p2}, La3/e;-><init>(Lbu/c;La3/h;Lkotlin/jvm/internal/b0;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v1, p0}, La3/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    sget-object v3, Lv3/b2;->d:Lv3/b2;

    .line 74
    .line 75
    if-eq v2, v3, :cond_1

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_1
    invoke-static {p0, v1}, Lv3/f;->C(Lv3/c2;Lay0/k;)V

    .line 79
    .line 80
    .line 81
    :goto_1
    iget-boolean p0, p2, Lkotlin/jvm/internal/b0;->d:Z

    .line 82
    .line 83
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    new-instance p2, Landroidx/collection/b;

    .line 87
    .line 88
    invoke-direct {p2, v0}, Landroidx/collection/b;-><init>(Landroidx/collection/g;)V

    .line 89
    .line 90
    .line 91
    :goto_2
    invoke-virtual {p2}, Landroidx/collection/b;->hasNext()Z

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    if-eqz v0, :cond_2

    .line 96
    .line 97
    invoke-virtual {p2}, Landroidx/collection/b;->next()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    check-cast v0, La3/h;

    .line 102
    .line 103
    invoke-virtual {v0, p1}, La3/h;->b1(Lbu/c;)V

    .line 104
    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_2
    return p0

    .line 108
    nop

    .line 109
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
