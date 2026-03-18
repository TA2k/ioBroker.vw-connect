.class public final synthetic Li50/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh50/i;

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lh50/i;ZZLjava/lang/String;II)V
    .locals 0

    .line 1
    iput p6, p0, Li50/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li50/b;->e:Lh50/i;

    .line 4
    .line 5
    iput-boolean p2, p0, Li50/b;->f:Z

    .line 6
    .line 7
    iput-boolean p3, p0, Li50/b;->g:Z

    .line 8
    .line 9
    iput-object p4, p0, Li50/b;->h:Ljava/lang/String;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Li50/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v5, p1

    .line 7
    check-cast v5, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const/4 p1, 0x1

    .line 15
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v6

    .line 19
    iget-object v1, p0, Li50/b;->e:Lh50/i;

    .line 20
    .line 21
    iget-boolean v2, p0, Li50/b;->f:Z

    .line 22
    .line 23
    iget-boolean v3, p0, Li50/b;->g:Z

    .line 24
    .line 25
    iget-object v4, p0, Li50/b;->h:Ljava/lang/String;

    .line 26
    .line 27
    invoke-static/range {v1 .. v6}, Li50/c;->l(Lh50/i;ZZLjava/lang/String;Ll2/o;I)V

    .line 28
    .line 29
    .line 30
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_0
    move-object v4, p1

    .line 34
    check-cast v4, Ll2/o;

    .line 35
    .line 36
    check-cast p2, Ljava/lang/Integer;

    .line 37
    .line 38
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    const/4 p1, 0x1

    .line 42
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 43
    .line 44
    .line 45
    move-result v5

    .line 46
    iget-object v0, p0, Li50/b;->e:Lh50/i;

    .line 47
    .line 48
    iget-boolean v1, p0, Li50/b;->f:Z

    .line 49
    .line 50
    iget-boolean v2, p0, Li50/b;->g:Z

    .line 51
    .line 52
    iget-object v3, p0, Li50/b;->h:Ljava/lang/String;

    .line 53
    .line 54
    invoke-static/range {v0 .. v5}, Li50/c;->m(Lh50/i;ZZLjava/lang/String;Ll2/o;I)V

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    nop

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
