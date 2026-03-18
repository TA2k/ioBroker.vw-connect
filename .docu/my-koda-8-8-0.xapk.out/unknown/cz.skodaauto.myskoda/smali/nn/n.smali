.class public final Lnn/n;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lnn/t;

.field public final synthetic h:Z

.field public final synthetic i:Lnn/s;

.field public final synthetic j:Lay0/k;

.field public final synthetic k:Lay0/k;

.field public final synthetic l:Lnn/b;

.field public final synthetic m:Lnn/a;

.field public final synthetic n:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lnn/t;Ljava/lang/Object;ZLnn/s;Lay0/k;Lay0/k;Lnn/b;Lnn/a;II)V
    .locals 0

    .line 1
    iput p10, p0, Lnn/n;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lnn/n;->g:Lnn/t;

    .line 4
    .line 5
    iput-object p2, p0, Lnn/n;->n:Ljava/lang/Object;

    .line 6
    .line 7
    iput-boolean p3, p0, Lnn/n;->h:Z

    .line 8
    .line 9
    iput-object p4, p0, Lnn/n;->i:Lnn/s;

    .line 10
    .line 11
    iput-object p5, p0, Lnn/n;->j:Lay0/k;

    .line 12
    .line 13
    iput-object p6, p0, Lnn/n;->k:Lay0/k;

    .line 14
    .line 15
    iput-object p7, p0, Lnn/n;->l:Lnn/b;

    .line 16
    .line 17
    iput-object p8, p0, Lnn/n;->m:Lnn/a;

    .line 18
    .line 19
    const/4 p1, 0x2

    .line 20
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 21
    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lnn/n;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v9, p1

    .line 7
    check-cast v9, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Lnn/n;->n:Ljava/lang/Object;

    .line 15
    .line 16
    move-object v2, p1

    .line 17
    check-cast v2, Lx2/s;

    .line 18
    .line 19
    const/16 p1, 0x6001

    .line 20
    .line 21
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 22
    .line 23
    .line 24
    move-result v10

    .line 25
    iget-object v1, p0, Lnn/n;->g:Lnn/t;

    .line 26
    .line 27
    iget-boolean v3, p0, Lnn/n;->h:Z

    .line 28
    .line 29
    iget-object v4, p0, Lnn/n;->i:Lnn/s;

    .line 30
    .line 31
    iget-object v5, p0, Lnn/n;->j:Lay0/k;

    .line 32
    .line 33
    iget-object v6, p0, Lnn/n;->k:Lay0/k;

    .line 34
    .line 35
    iget-object v7, p0, Lnn/n;->l:Lnn/b;

    .line 36
    .line 37
    iget-object v8, p0, Lnn/n;->m:Lnn/a;

    .line 38
    .line 39
    invoke-static/range {v1 .. v10}, Lnn/q;->b(Lnn/t;Lx2/s;ZLnn/s;Lay0/k;Lay0/k;Lnn/b;Lnn/a;Ll2/o;I)V

    .line 40
    .line 41
    .line 42
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    return-object p0

    .line 45
    :pswitch_0
    move-object v8, p1

    .line 46
    check-cast v8, Ll2/o;

    .line 47
    .line 48
    check-cast p2, Ljava/lang/Number;

    .line 49
    .line 50
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 51
    .line 52
    .line 53
    iget-object p1, p0, Lnn/n;->n:Ljava/lang/Object;

    .line 54
    .line 55
    move-object v1, p1

    .line 56
    check-cast v1, Landroid/widget/FrameLayout$LayoutParams;

    .line 57
    .line 58
    const p1, 0x90001c1

    .line 59
    .line 60
    .line 61
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 62
    .line 63
    .line 64
    move-result v9

    .line 65
    iget-object v0, p0, Lnn/n;->g:Lnn/t;

    .line 66
    .line 67
    iget-boolean v2, p0, Lnn/n;->h:Z

    .line 68
    .line 69
    iget-object v3, p0, Lnn/n;->i:Lnn/s;

    .line 70
    .line 71
    iget-object v4, p0, Lnn/n;->j:Lay0/k;

    .line 72
    .line 73
    iget-object v5, p0, Lnn/n;->k:Lay0/k;

    .line 74
    .line 75
    iget-object v6, p0, Lnn/n;->l:Lnn/b;

    .line 76
    .line 77
    iget-object v7, p0, Lnn/n;->m:Lnn/a;

    .line 78
    .line 79
    invoke-static/range {v0 .. v9}, Lnn/q;->a(Lnn/t;Landroid/widget/FrameLayout$LayoutParams;ZLnn/s;Lay0/k;Lay0/k;Lnn/b;Lnn/a;Ll2/o;I)V

    .line 80
    .line 81
    .line 82
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 83
    .line 84
    return-object p0

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
