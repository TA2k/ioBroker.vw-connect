.class public final Lk70/i1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lk70/x;


# direct methods
.method public constructor <init>(Lk70/x;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk70/i1;->a:Lk70/x;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ll70/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object p0, p0, Lk70/i1;->a:Lk70/x;

    .line 3
    .line 4
    if-nez p1, :cond_0

    .line 5
    .line 6
    check-cast p0, Li70/c;

    .line 7
    .line 8
    invoke-virtual {p0}, Li70/c;->b()V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Li70/c;->c:Lyy0/c2;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    sget-object p1, Li70/c;->i:Ll70/k;

    .line 17
    .line 18
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    check-cast p0, Li70/c;

    .line 23
    .line 24
    invoke-virtual {p0}, Li70/c;->b()V

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, Li70/c;->c:Lyy0/c2;

    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0, v0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Ll70/k;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lk70/i1;->a(Ll70/k;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
