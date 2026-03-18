.class public final synthetic Lf30/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Le30/v;

.field public final synthetic f:Z

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Le30/v;ZLay0/k;Lay0/k;I)V
    .locals 0

    .line 1
    iput p5, p0, Lf30/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lf30/j;->e:Le30/v;

    .line 4
    .line 5
    iput-boolean p2, p0, Lf30/j;->f:Z

    .line 6
    .line 7
    iput-object p3, p0, Lf30/j;->g:Lay0/k;

    .line 8
    .line 9
    iput-object p4, p0, Lf30/j;->h:Lay0/k;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lf30/j;->d:I

    .line 2
    .line 3
    check-cast p1, Lb1/a0;

    .line 4
    .line 5
    move-object v4, p2

    .line 6
    check-cast v4, Ll2/o;

    .line 7
    .line 8
    check-cast p3, Ljava/lang/Integer;

    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    const-string p2, "$this$AnimatedVisibility"

    .line 17
    .line 18
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const/4 v5, 0x0

    .line 22
    iget-object v0, p0, Lf30/j;->e:Le30/v;

    .line 23
    .line 24
    iget-boolean v1, p0, Lf30/j;->f:Z

    .line 25
    .line 26
    iget-object v2, p0, Lf30/j;->g:Lay0/k;

    .line 27
    .line 28
    iget-object v3, p0, Lf30/j;->h:Lay0/k;

    .line 29
    .line 30
    invoke-static/range {v0 .. v5}, Lf30/a;->a(Le30/v;ZLay0/k;Lay0/k;Ll2/o;I)V

    .line 31
    .line 32
    .line 33
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_0
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 37
    .line 38
    .line 39
    const-string p2, "$this$AnimatedVisibility"

    .line 40
    .line 41
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    const/4 v5, 0x0

    .line 45
    iget-object v0, p0, Lf30/j;->e:Le30/v;

    .line 46
    .line 47
    iget-boolean v1, p0, Lf30/j;->f:Z

    .line 48
    .line 49
    iget-object v2, p0, Lf30/j;->g:Lay0/k;

    .line 50
    .line 51
    iget-object v3, p0, Lf30/j;->h:Lay0/k;

    .line 52
    .line 53
    invoke-static/range {v0 .. v5}, Lf30/a;->b(Le30/v;ZLay0/k;Lay0/k;Ll2/o;I)V

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
