.class public final synthetic Lt90/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Z

.field public final synthetic g:Z


# direct methods
.method public synthetic constructor <init>(IZZ)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Lt90/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p2, p0, Lt90/b;->f:Z

    iput-boolean p3, p0, Lt90/b;->g:Z

    iput p1, p0, Lt90/b;->e:I

    return-void
.end method

.method public synthetic constructor <init>(IZZII)V
    .locals 0

    .line 2
    iput p5, p0, Lt90/b;->d:I

    iput p1, p0, Lt90/b;->e:I

    iput-boolean p2, p0, Lt90/b;->f:Z

    iput-boolean p3, p0, Lt90/b;->g:Z

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lt90/b;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    iget p2, p0, Lt90/b;->e:I

    .line 14
    .line 15
    or-int/lit8 p2, p2, 0x1

    .line 16
    .line 17
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    iget-boolean v0, p0, Lt90/b;->f:Z

    .line 22
    .line 23
    iget-boolean p0, p0, Lt90/b;->g:Z

    .line 24
    .line 25
    invoke-static {v0, p0, p1, p2}, Llp/se;->a(ZZLl2/o;I)V

    .line 26
    .line 27
    .line 28
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_0
    const/4 p2, 0x1

    .line 32
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 33
    .line 34
    .line 35
    move-result p2

    .line 36
    iget v0, p0, Lt90/b;->e:I

    .line 37
    .line 38
    iget-boolean v1, p0, Lt90/b;->f:Z

    .line 39
    .line 40
    iget-boolean p0, p0, Lt90/b;->g:Z

    .line 41
    .line 42
    invoke-static {v0, v1, p0, p1, p2}, Lt90/a;->e(IZZLl2/o;I)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :pswitch_1
    const/4 p2, 0x1

    .line 47
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 48
    .line 49
    .line 50
    move-result p2

    .line 51
    iget v0, p0, Lt90/b;->e:I

    .line 52
    .line 53
    iget-boolean v1, p0, Lt90/b;->f:Z

    .line 54
    .line 55
    iget-boolean p0, p0, Lt90/b;->g:Z

    .line 56
    .line 57
    invoke-static {v0, v1, p0, p1, p2}, Lt90/a;->d(IZZLl2/o;I)V

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
