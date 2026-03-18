.class public final synthetic Lew/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lew/i;


# direct methods
.method public synthetic constructor <init>(Lew/i;I)V
    .locals 0

    .line 1
    iput p2, p0, Lew/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lew/b;->e:Lew/i;

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
    .locals 3

    .line 1
    iget v0, p0, Lew/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Float;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    iget-object p0, p0, Lew/b;->e:Lew/i;

    .line 13
    .line 14
    iget-object v0, p0, Lew/i;->e:Ll2/f1;

    .line 15
    .line 16
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    add-float/2addr v2, p1

    .line 25
    invoke-virtual {p0, v2}, Lew/i;->b(F)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    sub-float/2addr v2, v1

    .line 33
    add-float/2addr v1, p1

    .line 34
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    cmpg-float v0, v1, v0

    .line 39
    .line 40
    if-nez v0, :cond_0

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    iget-object p0, p0, Lew/i;->l:Lyy0/q1;

    .line 44
    .line 45
    sub-float p1, v2, p1

    .line 46
    .line 47
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    invoke-virtual {p0, p1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move p1, v2

    .line 55
    :goto_0
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    :pswitch_0
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 61
    .line 62
    const-string v0, "$this$DisposableEffect"

    .line 63
    .line 64
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    new-instance p1, La2/j;

    .line 68
    .line 69
    const/4 v0, 0x4

    .line 70
    iget-object p0, p0, Lew/b;->e:Lew/i;

    .line 71
    .line 72
    invoke-direct {p1, p0, v0}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 73
    .line 74
    .line 75
    return-object p1

    .line 76
    nop

    .line 77
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
