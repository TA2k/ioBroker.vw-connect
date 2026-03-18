.class public final synthetic Ln70/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:C

.field public final synthetic e:Lxj0/f;

.field public final synthetic f:Z

.field public final synthetic g:Ljava/lang/Boolean;

.field public final synthetic h:Lay0/a;


# direct methods
.method public synthetic constructor <init>(CLxj0/f;ZLjava/lang/Boolean;Lay0/a;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-char p1, p0, Ln70/q;->d:C

    .line 5
    .line 6
    iput-object p2, p0, Ln70/q;->e:Lxj0/f;

    .line 7
    .line 8
    iput-boolean p3, p0, Ln70/q;->f:Z

    .line 9
    .line 10
    iput-object p4, p0, Ln70/q;->g:Ljava/lang/Boolean;

    .line 11
    .line 12
    iput-object p5, p0, Ln70/q;->h:Lay0/a;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    move-object v5, p1

    .line 2
    check-cast v5, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const/4 p1, 0x1

    .line 10
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 11
    .line 12
    .line 13
    move-result v6

    .line 14
    iget-char v0, p0, Ln70/q;->d:C

    .line 15
    .line 16
    iget-object v1, p0, Ln70/q;->e:Lxj0/f;

    .line 17
    .line 18
    iget-boolean v2, p0, Ln70/q;->f:Z

    .line 19
    .line 20
    iget-object v3, p0, Ln70/q;->g:Ljava/lang/Boolean;

    .line 21
    .line 22
    iget-object v4, p0, Ln70/q;->h:Lay0/a;

    .line 23
    .line 24
    invoke-static/range {v0 .. v6}, Ln70/a;->I(CLxj0/f;ZLjava/lang/Boolean;Lay0/a;Ll2/o;I)V

    .line 25
    .line 26
    .line 27
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0
.end method
