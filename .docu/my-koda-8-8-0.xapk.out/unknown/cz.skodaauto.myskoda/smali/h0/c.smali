.class public final Lh0/c;
.super Lh0/w0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final b:Lh0/z;

.field public final c:Lh0/t;


# direct methods
.method public constructor <init>(Lh0/z;Lh0/t;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lh0/w0;-><init>(Lh0/z;)V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh0/c;->b:Lh0/z;

    .line 5
    .line 6
    iput-object p2, p0, Lh0/c;->c:Lh0/t;

    .line 7
    .line 8
    invoke-interface {p2}, Lh0/t;->r()V

    .line 9
    .line 10
    .line 11
    sget-object p0, Lh0/t;->A0:Lh0/g;

    .line 12
    .line 13
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 14
    .line 15
    invoke-interface {p2, p0, p1}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Ljava/lang/Boolean;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    sget-object p0, Lh0/t;->B0:Lh0/g;

    .line 25
    .line 26
    invoke-interface {p2, p0, p1}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Ljava/lang/Boolean;

    .line 31
    .line 32
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 33
    .line 34
    .line 35
    return-void
.end method


# virtual methods
.method public final o()Lh0/z;
    .locals 0

    .line 1
    iget-object p0, p0, Lh0/c;->b:Lh0/z;

    .line 2
    .line 3
    return-object p0
.end method
