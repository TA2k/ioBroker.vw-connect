.class public final Lgz0/a;
.super Ljava/lang/IllegalArgumentException;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>(JLjava/lang/String;)V
    .locals 2

    .line 5
    const-string v0, "yyyy-MM-dd\'T\'HH:mm:ss.SSS"

    invoke-static {v0}, Lr11/a;->a(Ljava/lang/String;)Lr11/b;

    move-result-object v0

    new-instance v1, Ln11/j;

    invoke-direct {v1, p1, p2}, Ln11/j;-><init>(J)V

    invoke-virtual {v0, v1}, Lr11/b;->b(Lo11/a;)Ljava/lang/String;

    move-result-object p1

    if-eqz p3, :cond_0

    .line 6
    const-string p2, " ("

    const-string v0, ")"

    .line 7
    invoke-static {p2, p3, v0}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    goto :goto_0

    .line 8
    :cond_0
    const-string p2, ""

    .line 9
    :goto_0
    const-string p3, "Illegal instant due to time zone offset transition (daylight savings time \'gap\'): "

    .line 10
    invoke-static {p3, p1, p2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 11
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;I)V
    .locals 0

    packed-switch p2, :pswitch_data_0

    const-string p2, "message"

    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    return-void

    .line 2
    :pswitch_0
    const-string p2, "message"

    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/Exception;)V
    .locals 1

    const-string v0, "message"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    invoke-direct {p0, p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    return-void
.end method
