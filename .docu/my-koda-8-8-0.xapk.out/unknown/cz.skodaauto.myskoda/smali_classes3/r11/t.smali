.class public final Lr11/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr11/w;


# instance fields
.field public final d:Lr11/x;


# direct methods
.method public constructor <init>(Lr11/x;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lr11/t;->d:Lr11/x;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget-object p0, p0, Lr11/t;->d:Lr11/x;

    .line 2
    .line 3
    iget-object p0, p0, Lr11/x;->d:Lr11/w;

    .line 4
    .line 5
    invoke-interface {p0}, Lr11/w;->a()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final d(Lr11/s;Ljava/lang/CharSequence;I)I
    .locals 0

    .line 1
    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    iget-object p0, p0, Lr11/t;->d:Lr11/x;

    .line 6
    .line 7
    iget-object p0, p0, Lr11/x;->d:Lr11/w;

    .line 8
    .line 9
    invoke-interface {p0, p1, p2, p3}, Lr11/w;->d(Lr11/s;Ljava/lang/CharSequence;I)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method
