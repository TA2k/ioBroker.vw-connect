.class public final synthetic Lx30/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Z

.field public final synthetic l:Z

.field public final synthetic m:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;Lay0/a;Lay0/a;ZZLjava/lang/String;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lx30/d;->d:I

    .line 5
    .line 6
    iput-object p2, p0, Lx30/d;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Lx30/d;->f:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Lx30/d;->g:Ljava/lang/String;

    .line 11
    .line 12
    iput-object p5, p0, Lx30/d;->h:Lay0/k;

    .line 13
    .line 14
    iput-object p6, p0, Lx30/d;->i:Lay0/a;

    .line 15
    .line 16
    iput-object p7, p0, Lx30/d;->j:Lay0/a;

    .line 17
    .line 18
    iput-boolean p8, p0, Lx30/d;->k:Z

    .line 19
    .line 20
    iput-boolean p9, p0, Lx30/d;->l:Z

    .line 21
    .line 22
    iput-object p10, p0, Lx30/d;->m:Ljava/lang/String;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    move-object v10, p1

    .line 2
    check-cast v10, Ll2/o;

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
    move-result v11

    .line 14
    iget v0, p0, Lx30/d;->d:I

    .line 15
    .line 16
    iget-object v1, p0, Lx30/d;->e:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v2, p0, Lx30/d;->f:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v3, p0, Lx30/d;->g:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v4, p0, Lx30/d;->h:Lay0/k;

    .line 23
    .line 24
    iget-object v5, p0, Lx30/d;->i:Lay0/a;

    .line 25
    .line 26
    iget-object v6, p0, Lx30/d;->j:Lay0/a;

    .line 27
    .line 28
    iget-boolean v7, p0, Lx30/d;->k:Z

    .line 29
    .line 30
    iget-boolean v8, p0, Lx30/d;->l:Z

    .line 31
    .line 32
    iget-object v9, p0, Lx30/d;->m:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static/range {v0 .. v11}, Lx30/b;->a(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;Lay0/a;Lay0/a;ZZLjava/lang/String;Ll2/o;I)V

    .line 35
    .line 36
    .line 37
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0
.end method
