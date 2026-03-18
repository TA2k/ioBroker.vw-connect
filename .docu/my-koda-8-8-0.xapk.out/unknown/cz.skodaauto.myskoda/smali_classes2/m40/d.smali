.class public final Lm40/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lve0/u;

.field public final b:Lat0/f;


# direct methods
.method public constructor <init>(Lve0/u;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lm40/d;->a:Lve0/u;

    .line 5
    .line 6
    const-string v0, "PREF_FUELLING_TIMER_DURATION"

    .line 7
    .line 8
    const-wide/16 v1, 0x1

    .line 9
    .line 10
    invoke-virtual {p1, v1, v2, v0}, Lve0/u;->i(JLjava/lang/String;)Lub0/e;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    new-instance v0, Lat0/f;

    .line 15
    .line 16
    const/4 v1, 0x1

    .line 17
    invoke-direct {v0, p1, v1}, Lat0/f;-><init>(Lub0/e;I)V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Lm40/d;->b:Lat0/f;

    .line 21
    .line 22
    return-void
.end method
