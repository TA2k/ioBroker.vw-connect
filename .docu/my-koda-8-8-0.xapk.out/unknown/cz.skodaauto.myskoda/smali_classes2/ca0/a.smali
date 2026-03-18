.class public final synthetic Lca0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lba0/c;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lba0/c;Lay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lca0/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lca0/a;->e:Lba0/c;

    iput-object p2, p0, Lca0/a;->f:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lba0/c;Lay0/a;I)V
    .locals 0

    .line 2
    const/4 p3, 0x1

    iput p3, p0, Lca0/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lca0/a;->e:Lba0/c;

    iput-object p2, p0, Lca0/a;->f:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lca0/a;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 p2, 0x1

    .line 14
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    iget-object v0, p0, Lca0/a;->e:Lba0/c;

    .line 19
    .line 20
    iget-object p0, p0, Lca0/a;->f:Lay0/a;

    .line 21
    .line 22
    invoke-static {v0, p0, p1, p2}, Lca0/b;->c(Lba0/c;Lay0/a;Ll2/o;I)V

    .line 23
    .line 24
    .line 25
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result p2

    .line 32
    and-int/lit8 v0, p2, 0x3

    .line 33
    .line 34
    const/4 v1, 0x2

    .line 35
    const/4 v2, 0x1

    .line 36
    if-eq v0, v1, :cond_0

    .line 37
    .line 38
    move v0, v2

    .line 39
    goto :goto_0

    .line 40
    :cond_0
    const/4 v0, 0x0

    .line 41
    :goto_0
    and-int/2addr p2, v2

    .line 42
    move-object v8, p1

    .line 43
    check-cast v8, Ll2/t;

    .line 44
    .line 45
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    if-eqz p1, :cond_1

    .line 50
    .line 51
    iget-object p1, p0, Lca0/a;->e:Lba0/c;

    .line 52
    .line 53
    iget-object v2, p1, Lba0/c;->a:Ljava/lang/String;

    .line 54
    .line 55
    new-instance v4, Li91/w2;

    .line 56
    .line 57
    iget-object p0, p0, Lca0/a;->f:Lay0/a;

    .line 58
    .line 59
    const/4 p1, 0x3

    .line 60
    invoke-direct {v4, p0, p1}, Li91/w2;-><init>(Lay0/a;I)V

    .line 61
    .line 62
    .line 63
    const/4 v9, 0x0

    .line 64
    const/16 v10, 0x3bd

    .line 65
    .line 66
    const/4 v1, 0x0

    .line 67
    const/4 v3, 0x0

    .line 68
    const/4 v5, 0x0

    .line 69
    const/4 v6, 0x0

    .line 70
    const/4 v7, 0x0

    .line 71
    invoke-static/range {v1 .. v10}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 72
    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_1
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 76
    .line 77
    .line 78
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 79
    .line 80
    return-object p0

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
